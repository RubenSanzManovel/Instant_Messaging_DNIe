# discovery.py
import socket
import asyncio
import uuid  
from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser, AsyncServiceInfo
import config

class DiscoveryService:
    # Clase para descubrimiento de contactos
    def __init__(self, my_port, my_nick, on_peer_found_callback, my_ip=None):
        self.port = my_port # Puerto que utilizamos 
        self.nick = my_nick # Nickname que utilizamos(Será el del DNIe)
        self.on_peer = on_peer_found_callback # Callback para cuando encontramos un peer
        self.azc = None # AsyncZeroconf
        self.browser = None # AsyncServiceBrowser
        # Usar IP manual si se proporciona, sino autodetectar
        self.my_ip = my_ip if my_ip else self.get_lan_ip()
         
        # ID único para evitar choques si reinicias rápido el programa
        self.unique_id = str(uuid.uuid4())[:8]
        self.my_name = f"dni-im-{self.unique_id}.{config.SERVICE_TYPE}" # Nombre del servicio(Casi nunca se utiliza)

    def get_lan_ip(self):
        # Detecta la IP real de la LAN para anunciar correctamente.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # No se envía nada, solo se calcula la ruta hacia Google DNS
            s.connect(('8.8.8.8', 80)) # Se conecta a Google DNS
            ip = s.getsockname()[0] # Obtiene la IP
            s.close() # Cierra la conexión(Solo se utiliza para obtener la IP)
            return ip
        except Exception:
            return '127.0.0.1' # En el caso que no se encuentre es la de localhost

    async def start(self):
        print(f"🌐 [mDNS] Iniciando discovery en IP: {self.my_ip}")
        # Usamos AsyncZeroconf sin forzar interfaz específica para evitar errores en Windows
        try:
            self.azc = AsyncZeroconf()
        except Exception as e:
            print(f"⚠️ Error crítico mDNS: {e}")
            # Intentamos fallback sin argumentos si falla algo que no controlamos 
            self.azc = AsyncZeroconf()

        # Información de nuestro servicio
        info = ServiceInfo(
            config.SERVICE_TYPE,
            self.my_name,
            addresses=[socket.inet_aton(self.my_ip)],
            port=self.port,
            properties={"nick": self.nick},
            server=f"{socket.gethostname()}.local.",
        )
        
        try:
            await self.azc.async_register_service(info) # Registramos el servicio en el DNS
        except Exception as e:
            print(f"⚠️ [mDNS] Error registro en el servicio DNS: {e}") 
        
        # Empezamos a escuchar para descubrir otros servicios(Otros usuarios del chat)
        self.browser = AsyncServiceBrowser(
            self.azc.zeroconf, config.SERVICE_TYPE, handlers=[self.on_change]
        )

    def on_change(self, zeroconf, service_type, name, state_change):
        if state_change is not ServiceStateChange.Added: return # Solo nos interesa cuando se añade un servicio
        if name == self.my_name: return # Ignorarnos a nosotros mismos(No debería ocurrir)
        # Resolvemos el nombre encontrado en segundo plano
        asyncio.create_task(self.resolve(zeroconf, service_type, name)) # Resolvemos el nombre encontrado en segundo plano

    async def resolve(self, zeroconf, service_type, name):
        try:
            info = AsyncServiceInfo(service_type, name)     
            found = await info.async_request(zeroconf, 2000) # Esperamos hasta 2s para resolver
            
            if found and info.addresses:
                ip = socket.inet_ntoa(info.addresses[0])
                port = info.port
                
                # Intentar extraer nick de las propiedades
                peer_nick = name.split(".")[0]
                if info.properties and b'nick' in info.properties:
                    try:
                        nick_val = info.properties[b'nick']
                        if nick_val:
                            peer_nick = nick_val.decode('utf-8')
                    except: pass

                # Filtro: No añadirnos a nosotros mismos
                if ip == self.my_ip and port == self.port: return

                # Avisar a la TUI para mostrarlo
                self.on_peer(peer_nick, ip, port)
        except Exception: 
            pass

    async def stop(self):
        if self.browser: await self.browser.async_cancel()
        if self.azc: await self.azc.async_close()