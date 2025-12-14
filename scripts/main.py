# main.py
import asyncio
import sys
import config
from getpass import getpass

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from dnie_manager import DNIeManager
from protocol import SecureIMProtocol
from discovery import DiscoveryService
from tui import ChatTUI
from database import JsonDatabase

async def main():
    # Parsear argumentos: python main.py [IP] [PUERTO]
    manual_ip = None
    port = config.UDP_PORT
    
    if len(sys.argv) > 1:
        # Si hay un argumento y es una IP (contiene puntos)
        if '.' in sys.argv[1]:
            manual_ip = sys.argv[1]
            if len(sys.argv) > 2 and sys.argv[2].isdigit():
                port = int(sys.argv[2])
        # Si es solo un número, es el puerto
        elif sys.argv[1].isdigit():
            port = int(sys.argv[1])
    
    if manual_ip:
        print(f"--- DNIe CHAT (IP: {manual_ip}, Puerto {port}) ---")
    else:
        print(f"--- DNIe CHAT (Puerto {port}) ---")
    
    loop = asyncio.get_running_loop()
    dnie = None
    db = None
    try:
        pin = getpass("Introduce PIN DNIe: ")
        print("⌛ Leyendo tarjeta...")
        dnie = DNIeManager(pin)
        
        db = JsonDatabase(dnie)
        
        cert = x509.load_der_x509_certificate(dnie.cert_der, default_backend())
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            raw = cn_attrs[0].value
            my_nick = raw.replace("(AUTENTICACIÓN)", "").replace("(Autenticación)", "").replace("(FIRMA)", "").replace("(Firma)", "").strip()
        else:
            my_nick = "Usuario Desconocido"

    except Exception as e:
        print(f"Error al leer DNIe: {e}")
        sys.exit(1)

    def protocol_callback(addr, text, nombre, msg_id=None):
        tui.on_protocol_msg(addr, text, nombre, msg_id)

    protocol = SecureIMProtocol(dnie, db, protocol_callback)
    
    # Usar IP manual si se especificó, sino autodetectar
    if manual_ip:
        my_ip = manual_ip
    else:
        mdns_temp = DiscoveryService(port, my_nick, lambda n, i, p: None)
        my_ip = mdns_temp.get_lan_ip()
    
    tui = ChatTUI(protocol, my_nick, db, my_ip, port)
    
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=('0.0.0.0', port)
    )
    protocol.transport = transport 
    
    def discovery_callback(name, ip, p):
        contact_id = f"{ip}:{p}"
        existing = db.get_contact_info(contact_id)
        if existing and existing.get("name") == name:
            return
        tui.add_peer(name, ip, p)
        
    mdns = DiscoveryService(port, my_nick, discovery_callback, my_ip=my_ip if manual_ip else None)
    await mdns.start()

    try:
        await tui.run()
    finally:
        await mdns.stop()
 
if __name__ == "__main__":
    if sys.platform == 'win32':
        # Usar ProactorEventLoop en Windows para mejor manejo de UDP
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass