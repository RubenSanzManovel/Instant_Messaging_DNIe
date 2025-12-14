import asyncio
import struct
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import config

# Definición de los diferentes tipos de paquetes que tenemos
# IMPORTANTE: PKT_MSG y siguientes mantienen sus valores originales para compatibilidad
PKT_EPHEMERAL_KEY = 0x01      # Nueva fase 1: solo clave pública efímera (nuevo)
PKT_MSG = 0x02                # MANTIENE valor original
PKT_ACK = 0x04                # MANTIENE valor original
PKT_RECONNECT_REQ = 0x05      # MANTIENE valor original
PKT_RECONNECT_RESP = 0x06     # MANTIENE valor original
PKT_PENDING_SEND = 0x07       # MANTIENE valor original
PKT_PENDING_DONE = 0x08       # MANTIENE valor original
# Nuevos paquetes para handshake cifrado
PKT_HANDSHAKE_INIT = 0x10     # Fase 2: certificado cifrado (init)
PKT_HANDSHAKE_RESP = 0x11     # Fase 2: certificado cifrado (resp)

class SecureIMProtocol(asyncio.DatagramProtocol): # Clase que implementa el protolo de paso de mensajes seguro
    def __init__(self, dnie_manager, db, on_msg_callback):
        self.dnie = dnie_manager
        self.db = db
        self.transport = None
        self.callback = on_msg_callback
        self.sessions = {}
        self.my_cid = os.urandom(4)
        self.handshake_in_progress = {}
        self.reconnect_pending = {}
        self.role = {}
        self.pending_sent = {}
        # Claves efímeras para encriptar el certificado durante el handshake
        self.ephemeral_keys = {}  # {addr: {'private': key, 'peer_public': key, 'temp_cipher': cipher}}

    def connection_made(self, transport): # Al establecer la conexión
        self.transport = transport
        if self.callback:
            self.callback(None, "SESSIONS_READY", "System", None)

    def datagram_received(self, data, addr): # Al recibir un paquete
        if len(data) < 5:
            return
        msg_type = data[0]
        payload = data[5:]
        
        self.touch_session(addr)
        
        if msg_type == PKT_EPHEMERAL_KEY:
            self.handle_ephemeral_key(payload, addr)
        elif msg_type == PKT_HANDSHAKE_INIT:
            asyncio.create_task(self.handle_handshake(payload, addr, is_response=False))
        elif msg_type == PKT_HANDSHAKE_RESP:
            asyncio.create_task(self.handle_handshake(payload, addr, is_response=True))
        elif msg_type == PKT_MSG:
            self.handle_message(payload, addr)
        elif msg_type == PKT_ACK:
            self.handle_ack(payload, addr)
        elif msg_type == PKT_RECONNECT_REQ:
            asyncio.create_task(self.handle_reconnect_req(payload, addr))
        elif msg_type == PKT_RECONNECT_RESP:
            asyncio.create_task(self.handle_reconnect_resp(payload, addr))
        elif msg_type == PKT_PENDING_SEND:
            asyncio.create_task(self.handle_pending_send(payload, addr))
        elif msg_type == PKT_PENDING_DONE:
            self.handle_pending_done(payload, addr)

    def touch_session(self, addr): # Actualiza el timestamp para evitar timeout mientras hablamos
        if addr in self.reconnect_pending:
            self.reconnect_pending[addr]['timestamp'] = asyncio.get_event_loop().time()

    def handle_ephemeral_key(self, payload, addr):
        """Fase 1: Recibe la clave pública efímera del peer"""
        try:
            if len(payload) < 32:
                return
            
            peer_ephemeral_pub_bytes = payload[:32]
            
            # Determinar si soy el iniciador o el responder
            is_initiator = addr in self.ephemeral_keys
            
            # Generar mi clave efímera si no existe (soy el responder)
            if not is_initiator:
                my_ephemeral_private = x25519.X25519PrivateKey.generate()
                self.ephemeral_keys[addr] = {
                    'private': my_ephemeral_private,
                    'public_bytes': my_ephemeral_private.public_key().public_bytes_raw()
                }
                # Enviar mi clave efímera de vuelta
                packet = struct.pack("B", PKT_EPHEMERAL_KEY) + self.my_cid + self.ephemeral_keys[addr]['public_bytes']
                self.transport.sendto(packet, addr)
            
            # Calcular secreto compartido efímero
            peer_ephemeral_key = x25519.X25519PublicKey.from_public_bytes(peer_ephemeral_pub_bytes)
            ephemeral_shared = self.ephemeral_keys[addr]['private'].exchange(peer_ephemeral_key)
            temp_key = hashlib.blake2s(ephemeral_shared, digest_size=32).digest()
            
            # Crear cifrador temporal para el certificado
            self.ephemeral_keys[addr]['temp_cipher'] = ChaCha20Poly1305(temp_key)
            self.ephemeral_keys[addr]['peer_public'] = peer_ephemeral_pub_bytes
            
            # Enviar certificado cifrado INMEDIATAMENTE
            if is_initiator:
                # Soy el iniciador: envío HANDSHAKE_INIT
                self.enviar_paquete_credenciales(addr[0], addr[1], tipo=PKT_HANDSHAKE_INIT)
            else:
                # Soy el responder: envío HANDSHAKE_RESP
                self.enviar_paquete_credenciales(addr[0], addr[1], tipo=PKT_HANDSHAKE_RESP)
            
        except Exception:
            pass
    
    async def handle_handshake(self, payload, addr, is_response): # Lo que ocurre en el handshake
        if addr in self.sessions:
            return
        
        # Verificar que tenemos clave efímera establecida
        if addr not in self.ephemeral_keys or 'temp_cipher' not in self.ephemeral_keys[addr]:
            return
        
        try:
            temp_cipher = self.ephemeral_keys[addr]['temp_cipher']
            offset = 0
            
            # Extraer y descifrar el certificado cifrado
            if len(payload) < 44:  # 32 (pub key) + 12 (nonce) mínimo
                return
            
            peer_pub_bytes = payload[offset:offset+32]
            offset += 32
            
            nonce = payload[offset:offset+12]
            offset += 12
            
            encrypted_cert = payload[offset:]
            
            # Descifrar el certificado
            try:
                cert_bytes = temp_cipher.decrypt(nonce, encrypted_cert, None)
            except Exception:
                # Error al descifrar: posible ataque o corrupción
                if addr in self.ephemeral_keys:
                    del self.ephemeral_keys[addr]
                return
            
            try:
                cert_obj = x509.load_der_x509_certificate(cert_bytes, default_backend()) # Carga del certificado
                cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME) # Obtención de información del dni
                if cn_attrs:
                    raw = str(cn_attrs[0].value)
                    nombre = raw.replace("(AUTENTICACIÓN)", "").replace("(Autenticación)", "").replace("(FIRMA)", "").replace("(Firma)", "").strip() # Nos quedamos con el nombre limpio
                else:
                    nombre = "DNIe Desconocido"
            except:
                nombre = "Error Certificado"
            
            peer_key_obj = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes) # Obtención de la clave pública del otro usuario
            shared_secret = self.dnie.private_key.exchange(peer_key_obj) # Secreto compartido  que solo conocen los dos usuarios, con mi clave privada y la del otro usuario
            session_key = hashlib.blake2s(shared_secret, digest_size=32).digest() # Generación de la clave de sesión
            
            self.sessions[addr] = { # Guardamos la sesión
                'cipher': ChaCha20Poly1305(session_key),
                'name': nombre,
                'state': 'ESTABLISHED'
            }
            
            existing_cn = None
            all_contacts = self.db.get_all_contacts()
            for cn, info in all_contacts.items():
                if info.get("ip") == addr[0] and info.get("port") == addr[1]:
                    existing_cn = cn
                    break
            
            contact_id = existing_cn if existing_cn else nombre
            self.db.add_or_update_contact(
                contact_id,
                name=nombre,
                ip=addr[0],
                port=addr[1],
                session_key=session_key.hex(),
                peer_cert=cert_bytes.hex()
            )
            
            if is_response: # Si somos los que iniciamos el handshake
                self.role[addr] = "initiator"
                cb_msg = "HANDSHAKE_OK_INIT"
            else:
                self.role[addr] = "responder" # Si respondemos al handshake
                cb_msg = "HANDSHAKE_OK_RESP"
            
            if self.callback:
                self.callback(addr, cb_msg, nombre, None)
            
            # Limpiar clave efímera después de todo
            if addr in self.ephemeral_keys:
                del self.ephemeral_keys[addr]
                
        except Exception:
            pass

    def handle_message(self, payload, addr): # Manejamos el mensaje que nos llega 
        if addr not in self.sessions:
            return
        session = self.sessions[addr]
        cipher = session['cipher']
        nombre = session.get('name', 'Unknown')
        try:
            nonce = payload[:12]
            ciphertext = payload[12:]
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            msg_data = plaintext.decode('utf-8')
            
            if '|' in msg_data:
                msg_id, msg = msg_data.split('|', 1)
                self.enviar_ack(addr[0], addr[1], msg_id)
            else:
                msg_id = None
                msg = msg_data
            
            if self.callback:
                self.callback(addr, msg, nombre, msg_id)
        except:
            pass

    def enviar_handshake(self, ip, port, cn=None): # Enviamos el handshake 
        addr = (ip, port)

        if addr in self.sessions:
            if self.callback:
                contact_name = self.sessions[addr].get('name', 'Unknown')
                self.callback(addr, "SESSIONS_OK", contact_name, None)
            return True
        
        saved_key = None
        contact_name = None
        
        if cn:
            contact_info = self.db.get_contact_info(cn)
            if contact_info:
                saved_key = contact_info.get("session_key")
                contact_name = contact_info.get("name", cn)
        
        if not saved_key:
            all_contacts = self.db.get_all_contacts()
            for name, info in all_contacts.items():
                if info.get("ip") == ip and info.get("port") == port:
                    saved_key = info.get("session_key")
                    if saved_key:
                        contact_name = info.get("name", name)
                        break
        
        if saved_key: 
            try:
                if isinstance(saved_key, str):
                    session_key = bytes.fromhex(saved_key)
                else:
                    session_key = saved_key

                self.sessions[addr] = {
                    'cipher': ChaCha20Poly1305(session_key),
                    'name': contact_name,
                    'state': 'ESTABLISHED'
                }
                
                final_cn = cn if cn else contact_name
                
                self.reconnect_pending[addr] = {
                    'cn': final_cn,
                    'timestamp': asyncio.get_event_loop().time()
                }
                
                self.enviar_reconnect_req(ip, port)
                return True
            except Exception:
                pass
        
        # Fase 1: Enviar clave efímera primero
        self.enviar_clave_efimera(ip, port)
        return False
    
    def enviar_clave_efimera(self, ip, port):
        """Fase 1: Envía solo la clave pública efímera para establecer canal cifrado"""
        if not self.transport:
            return
        try:
            addr = (ip, port)
            # Generar nueva clave efímera para este handshake
            my_ephemeral_private = x25519.X25519PrivateKey.generate()
            public_bytes = my_ephemeral_private.public_key().public_bytes_raw()
            
            self.ephemeral_keys[addr] = {
                'private': my_ephemeral_private,
                'public_bytes': public_bytes
            }
            
            # Enviar solo la clave pública efímera
            packet = struct.pack("B", PKT_EPHEMERAL_KEY) + self.my_cid + public_bytes
            self.transport.sendto(packet, (ip, port))
            # El certificado se enviará automáticamente cuando reciba la clave efímera del peer
        except Exception:
            pass

    def cerrar_sesion(self, ip, port): # Cerramos sesión
        addr = (ip, port)
        if addr in self.sessions:
            del self.sessions[addr]
        if addr in self.reconnect_pending:
            del self.reconnect_pending[addr]
        if addr in self.role:
            del self.role[addr]
        if addr in self.pending_sent:
            del self.pending_sent[addr]

    def tiene_sesion(self, ip, port): # Comprobamos que haya sesión 
        addr = (ip, port)
        return addr in self.sessions

    def enviar_paquete_credenciales(self, ip, port, tipo): # Fase 2: Mandamos el certificado CIFRADO
        if not self.transport:
            return
        addr = (ip, port)
        
        # Verificar que tenemos clave efímera establecida
        if addr not in self.ephemeral_keys or 'temp_cipher' not in self.ephemeral_keys[addr]:
            return
        
        try:
            cert, firma = self.dnie.obtener_credenciales()
            temp_cipher = self.ephemeral_keys[addr]['temp_cipher']
            
            # Cifrar el certificado con la clave temporal
            nonce = os.urandom(12)
            encrypted_cert = temp_cipher.encrypt(nonce, cert, None)
            
            # Paquete: tipo | cid | public_key_X25519 | nonce | certificado_cifrado
            packet = (
                struct.pack("B", tipo) + self.my_cid + 
                self.dnie.public_bytes + nonce + encrypted_cert
            )
            self.transport.sendto(packet, (ip, port))
        except Exception:
            pass

    def enviar_mensaje(self, ip, port, texto, msg_id=None): # Encio del mensaje
        addr = (ip, port)
        if addr not in self.sessions:
            return False
        try:
            cipher = self.sessions[addr]['cipher']
            nonce = os.urandom(12)
            msg_data = f"{msg_id}|{texto}" if msg_id else texto
            ciphertext = cipher.encrypt(nonce, msg_data.encode('utf-8'), None) # Encriptamos con la clave compartida
            packet = struct.pack("B", PKT_MSG) + self.my_cid + nonce + ciphertext
            self.transport.sendto(packet, addr)
            return True
        except:
            return False

    def enviar_ack(self, ip, port, msg_id): # Mandamos ACK cifrado 
        addr = (ip, port)
        if addr not in self.sessions:
            return
        try:
            cipher = self.sessions[addr]['cipher']
            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(nonce, msg_id.encode('utf-8'), None)
            packet = struct.pack("B", PKT_ACK) + self.my_cid + nonce + ciphertext
            self.transport.sendto(packet, addr)
        except:
            pass

    def handle_ack(self, payload, addr): # Manejamos los ack que recibimos
        if addr not in self.sessions:
            return
        session = self.sessions[addr]
        cipher = session['cipher']
        nombre = session.get('name', 'Unknown')
        try:
            nonce = payload[:12]
            ciphertext = payload[12:]
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            msg_id = plaintext.decode('utf-8')
            if self.callback:
                self.callback(addr, f"ACK|{msg_id}", nombre, None)
        except:
            pass

    def enviar_reconnect_req(self, ip, port): # Enviamos el paquete de tipo reconnect request
        if not self.transport:
            return
        packet = struct.pack("B", PKT_RECONNECT_REQ) + self.my_cid
        self.transport.sendto(packet, (ip, port))

    def enviar_reconnect_resp(self, ip, port): # Enviamos el paqeute de tipo reconnct response
        if not self.transport:
            return
        packet = struct.pack("B", PKT_RECONNECT_RESP) + self.my_cid
        self.transport.sendto(packet, (ip, port))

    async def handle_reconnect_req(self, payload, addr):
        # Recibe REQ: si tengo session_key guardada, restauro y respondo si no da error(Evitamos man in the middle)
        all_contacts = self.db.get_all_contacts()
        for cn, info in all_contacts.items():
            if info.get("ip") == addr[0] and info.get("port") == addr[1] and info.get("session_key"):
                try:
                    session_key = bytes.fromhex(info.get("session_key"))
                    self.sessions[addr] = {
                        'cipher': ChaCha20Poly1305(session_key),
                        'name': info.get("name", cn),
                        'state': 'ESTABLISHED'
                    }
                    self.db.set_contact_connected(cn, True)
                    self.role[addr] = "responder"
                    self.enviar_reconnect_resp(addr[0], addr[1])
                    if self.callback:
                        self.callback(addr, "SESSION_RESTORED_RESP", info.get("name", cn), None)
                    return
                except Exception:
                    pass

    async def handle_reconnect_resp(self, payload, addr):
        # Recibe RESP a mi REQ: confirmo que soy initiator
        if addr in self.reconnect_pending:
            info = self.reconnect_pending.pop(addr)
            cn = info['cn']
            if addr in self.sessions:
                self.role[addr] = "initiator"
                session = self.sessions[addr]
                self.db.set_contact_connected(cn, True)
                if self.callback:
                    self.callback(addr, "SESSION_RESTORED_INIT", session.get("name", "Unknown"), None)

    def enviar_pending_send(self, ip, port):
        # Avisa que voy a enviar pendientes
        if not self.transport:
            return
        try:
            packet = struct.pack("B", PKT_PENDING_SEND) + self.my_cid
            self.transport.sendto(packet, (ip, port))
        except Exception:
            pass

    def enviar_pending_done(self, ip, port):
        # Avisa que terminé de enviar pendientes
        if not self.transport:
            return
        try:
            packet = struct.pack("B", PKT_PENDING_DONE) + self.my_cid
            self.transport.sendto(packet, (ip, port))
        except Exception:
            pass

    async def handle_pending_send(self, payload, addr):
        # Recibe PENDING_SEND: el peer va a mandar sus pendientes
        if addr not in self.sessions:
            return
        session = self.sessions[addr]
        nombre = session.get('name', 'Unknown')
        if self.callback:
            self.callback(addr, "PEER_SENDING_PENDING", nombre, None)

    def handle_pending_done(self, payload, addr):
        # Recibe PENDING_DONE: el peer terminó de mandar sus pendientes
        if addr not in self.sessions:
            return
        session = self.sessions[addr]
        nombre = session.get('name', 'Unknown')
        
        if not self.pending_sent.get(addr, False):
            self.pending_sent[addr] = True
            if self.callback:
                self.callback(addr, "SEND_MY_PENDING", nombre, None)

    async def check_reconnect_timeouts(self):
        # Comprueba los timeouts de los reconnets
        while True:
            await asyncio.sleep(1)
            
            current_time = asyncio.get_event_loop().time()
            timeout_addrs = []
            
            for addr, info in list(self.reconnect_pending.items()):
                if current_time - info['timestamp'] > 0.1:
                    timeout_addrs.append(addr)
            
            for addr in timeout_addrs:
                info = self.reconnect_pending.pop(addr)
                cn = info['cn']
                
                if addr in self.sessions:
                    del self.sessions[addr]
                
                if self.callback:
                    self.callback(addr, "RECONNECT_TIMEOUT", cn, None)