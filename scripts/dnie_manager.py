# dnie_manager.py
import sys
from pkcs11 import lib as pkcs11_lib, ObjectClass, Attribute, Mechanism
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import config
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

class DNIeManager:
    def __init__(self, pin: str):
        self.pin = pin
        self.lib_path = config.PKCS11_LIB_PATH 
        
        # Generar claves efímeras
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Intentamos extraer credenciales. Si falla, el error sube (no hacemos sys.exit)
        self.cert_der, self.firma_cached = self.extraer_credenciales()

    def get_token(self): # Obtenemos el token
        pkcs11 = pkcs11_lib(self.lib_path)
        slots = pkcs11.get_slots(token_present=True)
        if not slots:
            raise RuntimeError("No se detecta tarjeta DNIe.")
        return slots[config.SLOT_INDEX].get_token()

    def extraer_credenciales(self): # Extraemos credenciales
        token = self.get_token()
        with token.open(user_pin=self.pin, rw=True) as session:
            certs = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
            if not certs: raise RuntimeError("No certificados.")
            cert_der = certs[0][Attribute.VALUE] 

            keys = list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            if not keys: raise RuntimeError("No clave privada.")

            priv_key = keys[0] # Usamos la clave de autenticación
            
            firma = priv_key.sign(self.public_bytes, mechanism=Mechanism.SHA256_RSA_PKCS)
            return cert_der, firma
    
    def obtener_credenciales(self):
        # Obtenemos las credenciales necesarias
        return self.cert_der, self.firma_cached

    def get_user_name(self):
        # Extraer nombre para mostrarlo
        try:
            cert = x509.load_der_x509_certificate(self.cert_der, default_backend())
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return cn.replace("(AUTENTICACIÓN)", "").strip()
        except:
            return "Usuario DNIe"

    def get_serial_number(self):
        # Devuelve el número de serie del certificado para el nombre de la base de datos 
        cert = x509.load_der_x509_certificate(self.cert_der, default_backend())
        return cert.serial_number
 
    def sign_data(self, data: bytes) -> bytes:
        # Firma datos arbitrarios usando la clave privada del DNIe
        token = self.get_token()
        with token.open(user_pin=self.pin, rw=True) as session:
            keys = list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            if not keys:
                raise RuntimeError("No clave privada.")
            priv_key = keys[1]
            return priv_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)