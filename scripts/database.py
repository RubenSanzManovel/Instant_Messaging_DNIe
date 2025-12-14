import json
import os
import uuid
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class JsonDatabase:
    AES_KEY_SIZE = 32  # 256 bits para K_db
    C_FILENAME = "C_value_chat.bin"
    
    def __init__(self, dnie_manager):
        self.dnie_manager = dnie_manager
        self.data = {"contacts": {}}
        
        # Calcular nombre de archivo basado en el hash del número de serie para que sea unico por DNIe
        serial = self.dnie_manager.get_serial_number()
        serial_hash = hashlib.sha256(str(serial).encode()).hexdigest()[:16]
        
        # Archivos: igual que en el gestor de contraseñas
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.archivo_C = os.path.join(script_dir, self.C_FILENAME)
        self.archivo_kdb = os.path.join(script_dir, f"kdb_enc_{serial_hash}.bin")
        self.filepath = os.path.join(script_dir, f"database_{serial_hash}.json.enc")
        
        self.k_db_cache = None  # Caché para K_db
        
        # Inicializar C y K_db igual que el gestor
        self.inicializar_C()
        self.inicializar_kdb()
        
        self.load()
    
    def inicializar_C(self):
        # Crea el challenge C si no existe
        if os.path.exists(self.archivo_C):
            return
        C = os.urandom(8)  # 64 bits (8 bytes)
        with open(self.archivo_C, "wb") as f:
            f.write(C)
    
    def leer_C(self) -> bytes:
        # Lee C siempre que no haya sido modificado el archivo
        with open(self.archivo_C, "rb") as f:
            data = f.read()
        if len(data) != 8:
            raise RuntimeError("Valor C inválido (longitud incorrecta).")
        return data
    
    def inicializar_kdb(self):
        # Crea la Kdb
        if os.path.exists(self.archivo_kdb):
            return
        
        # Crear K_db aleatoria de 256 bits
        k_db = os.urandom(self.AES_KEY_SIZE)
        
        # Firmar C para obtener K
        C = self.leer_C()
        S = self.dnie_manager.sign_data(C)
        K = hashlib.sha256(S).digest()
        
        # Cifrar K_db con K usando AES-GCM (Similar a como lo haciamos en el gestor de contraseñas)
        aesgcm = AESGCM(K)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, k_db, associated_data=None)
        
        # Guardar nonce + ct
        with open(self.archivo_kdb, "wb") as f:
            f.write(nonce + ct)
        
        self.k_db_cache = k_db
    
    def descifrar_kdb(self) -> bytes:
        # Descifra la Kdb como haciamos en el gestor
        if self.k_db_cache is not None:
            return self.k_db_cache
        
        if not os.path.exists(self.archivo_kdb):
            raise RuntimeError("No existe la clave k_db cifrada para este DNI.")
        
        # Leemos el nonce y el texto cifrado( COmo en el gestor)
        with open(self.archivo_kdb, "rb") as f:
            contenido = f.read()
        nonce = contenido[:12]
        ct = contenido[12:]
        
        # Firmar C para recuperar K
        C = self.leer_C()
        S = self.dnie_manager.sign_data(C)
        K = hashlib.sha256(S).digest()
        
        # Descifrar K_db
        aesgcm = AESGCM(K)
        k_db = aesgcm.decrypt(nonce, ct, associated_data=None)
        
        self.k_db_cache = k_db
        return k_db

    def load(self):
        # Carga la base de datos cifrada con K_db (igual que gestor de contraseñas)
        k_db = self.descifrar_kdb()
        
        if not os.path.exists(self.filepath):
            self.data = {"contacts": {}}
            return
        
        try:
            with open(self.filepath, "rb") as f:
                contenido = f.read()
            
            if not contenido:
                self.data = {"contacts": {}}
                return
            
            # Descifrar con K_db usando AES-GCM
            nonce = contenido[:12]
            ct = contenido[12:]
            aesgcm = AESGCM(k_db)
            datos_bytes = aesgcm.decrypt(nonce, ct, associated_data=None)
            self.data = json.loads(datos_bytes.decode("utf-8"))
            
            if "contacts" not in self.data:
                self.data["contacts"] = {}
            self.clean_duplicates()
        except Exception as e:
            print(f"Error al cargar DB cifrada: {e}")
            self.data = {"contacts": {}}

    def save(self):
        # Guarda la base de datos cifrada con K_db (igual que gestor de contraseñas)
        try:
            k_db = self.descifrar_kdb()
            
            # Cifrar con K_db usando AES-GCM
            aesgcm = AESGCM(k_db)
            nonce = os.urandom(12)
            json_str = json.dumps(self.data, indent=2, ensure_ascii=False)
            ct = aesgcm.encrypt(nonce, json_str.encode("utf-8"), associated_data=None)
            
            # Guardar nonce + ct
            with open(self.filepath, "wb") as f:
                f.write(nonce + ct)
        except Exception as e:
            print(f"Error al guardar DB: {e}")

    def get_all_contacts(self):
        return self.data.get("contacts", {})

    def add_or_update_contact(self, cn, **kwargs):
        if cn not in self.data["contacts"]:
            self.data["contacts"][cn] = {
                "name": kwargs.get("name", cn),
                "ip": kwargs.get("ip"),
                "port": kwargs.get("port"),
                "msgs": [],
                "is_connected": False,
                "last_seen": None,
                "session_key": None,
                "peer_cert": None
            }
        else:
            for key, value in kwargs.items():
                if key in ["name", "ip", "port", "session_key", "peer_cert"]:
                    self.data["contacts"][cn][key] = value
        self.save()

    def set_contact_connected(self, cn, connected):
        # Pone el contacto como conectado
        if cn in self.data["contacts"]:
            self.data["contacts"][cn]["is_connected"] = connected
            if not connected:
                self.data["contacts"][cn]["last_seen"] = datetime.now().isoformat()
            self.save()

    def add_message(self, cn, sender, text, status="received", timestamp=None, msg_id=None):
        # Añade los mensajes a la base de datos
        if cn not in self.data["contacts"]:
            self.add_or_update_contact(cn)
        
        if msg_id:
            for existing_msg in self.data["contacts"][cn]["msgs"]:
                if existing_msg.get("id") == msg_id:
                    return msg_id
        else:
            msg_id = str(uuid.uuid4())
        
        msg = {
            "id": msg_id,
            "sender": sender,
            "text": text,
            "timestamp": timestamp or datetime.now().isoformat(),
            "status": status,
            "read": False,
            "sent_timestamp": datetime.now().timestamp() if status == "sent" else None
        }
        self.data["contacts"][cn]["msgs"].append(msg)
        self.save()
        return msg_id

    def get_history(self, cn):
        # Obtiene el historial de mensajes para un contacto
        if cn not in self.data["contacts"]:
            return []
        return self.data["contacts"][cn].get("msgs", [])

    def mark_message_status(self, cn, msg_id, status):
        # Ponemos el mensaje en el estatus que le corresponde 
        if cn not in self.data["contacts"]:
            return
        for msg in self.data["contacts"][cn]["msgs"]:
            if msg.get("id") == msg_id:
                msg["status"] = status
                if status == "sent":
                    msg["sent_timestamp"] = datetime.now().timestamp()
                elif status == "delivered":
                    msg["sent_timestamp"] = None
                elif status == "pending":
                    msg["sent_timestamp"] = None
                self.save()
                return
 
    def get_pending_messages(self, cn):
        # Obtenemos mensajes pendientes
        return [m for m in self.get_history(cn) if m["status"] == "pending"]

    def get_unread_count(self, cn, my_nick):
        # Obtenemos mensajes que no han sido leidos
        if cn not in self.data["contacts"]:
            return 0
        msgs = self.data["contacts"][cn]["msgs"]
        return sum(1 for m in msgs if m.get("status") == "received" and not m.get("read", False))

    def mark_messages_as_read(self, cn, my_nick):
        # Marcamos los mensajes como leidos
        if cn not in self.data["contacts"]:
            return
        msgs = self.data["contacts"][cn]["msgs"]
        changed = False
        for m in msgs:
            if m.get("status") == "received" and not m.get("read", False):
                m["read"] = True
                changed = True
        if changed:
            self.save()

    def mark_message_as_read_by_id(self, cn, msg_id):
        # Marcamos los mensajes como leidos en función de su ip
        if cn not in self.data["contacts"]:
            return
        for msg in self.data["contacts"][cn]["msgs"]:
            if msg.get("id") == msg_id:
                msg["read"] = True
                self.save()
                return

    def check_message_timeouts(self, cn, timeout_seconds=2):
        # Marcamos el timeout de los mensajes
        if cn not in self.data["contacts"]:
            return False
        now = datetime.now().timestamp()
        has_timeout = False
        for msg in self.data["contacts"][cn]["msgs"]:
            if msg.get("status") == "sent" and msg.get("sent_timestamp"):
                elapsed = now - msg["sent_timestamp"]
                if elapsed > timeout_seconds:
                    msg["status"] = "pending"
                    msg["sent_timestamp"] = None
                    has_timeout = True
        if has_timeout:
            self.save()
        return has_timeout

    def get_session_key(self, cn):
        # Obtiene la session_key guardada para un contacto es decir, la clave compartida
        contact = self.data["contacts"].get(cn, {})
        session_key_hex = contact.get("session_key")
        if session_key_hex:
            return session_key_hex  # Devuelve como string hex, protocol.py lo convierte
        return None

    def get_contact_info(self, cn):
        # Obtiene toda la info de un contacto
        return self.data["contacts"].get(cn,{})

    def get_peer_cert(self, cn):
        # Obtenemos el certificado del peer
        if cn not in self.data["contacts"]:
            return None
        cert_hex = self.data["contacts"][cn].get("peer_cert")
        if cert_hex:
            return bytes.fromhex(cert_hex)
        return None

    def clean_duplicates(self):
        # Eliminamos duplicados(limpieza y organización de la TUI)
        contacts_to_remove = []
        contacts_by_name = {}
        for cn, info in list(self.data["contacts"].items()):
            name = info.get("name")
            if name:
                if name not in contacts_by_name:
                    contacts_by_name[name] = []
                contacts_by_name[name].append(cn)
        for name, contact_ids in contacts_by_name.items():
            if len(contact_ids) > 1:
                best_cn = None
                max_msgs = -1
                for cn in contact_ids:
                    msgs_count = len(self.data["contacts"][cn].get("msgs", []))
                    if msgs_count > max_msgs:
                        max_msgs = msgs_count
                        best_cn = cn
                if max_msgs == 0:
                    for cn in contact_ids:
                        if ":" in cn:
                            best_cn = cn
                            break
                for cn in contact_ids:
                    if cn != best_cn:
                        contacts_to_remove.append(cn)
        for cn in contacts_to_remove:
            if cn in self.data["contacts"]:
                del self.data["contacts"][cn]
        if contacts_to_remove:
            self.save()
