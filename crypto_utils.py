# crypto_utils.py
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import secrets
import hashlib

class CryptoUtils:
    @staticmethod
    def generate_ecdh_key_pair():
        """Gera par de chaves ECDHE usando curva P-256"""
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # Curva P-256
            default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        """Serializa chave pública para bytes"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_public_key(pem_data):
        """Desserializa chave pública de bytes"""
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
    
    @staticmethod
    def generate_rsa_certificate():
        """Gera certificado RSA autoassinado"""
        # Gera chave privada RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Cria certificado autoassinado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
            x509.NameAttribute(NameOID.COMMON_NAME, "securechat.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return private_key, cert
    
    @staticmethod
    def sign_data(private_key, data):
        """Assina dados com chave privada RSA"""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(public_key, data, signature):
        """Verifica assinatura com chave pública RSA"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def derive_shared_secret(private_key, peer_public_key):
        """Deriva segredo compartilhado ECDHE"""
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret
    
    @staticmethod
    def derive_keys(shared_secret, salt=None, info=b"handshake data"):
        """Deriva chaves usando HKDF (TLS 1.3 style)"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Deriva chave mestra
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        master_key = hkdf.derive(shared_secret)
        
        # Deriva chaves direcionais
        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 2 chaves de 32 bytes
            salt=b"",
            info=b"key derivation",
            backend=default_backend()
        ).derive(master_key)
        
        key_c2s = key_material[:32]  # Cliente para servidor
        key_s2c = key_material[32:]  # Servidor para cliente
        
        return key_c2s, key_s2c, salt