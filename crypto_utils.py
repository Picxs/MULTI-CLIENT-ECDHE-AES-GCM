# crypto_utils.py
"""
Utilitários criptográficos para o projeto MULTI-CLIENT-ECDHE-AES-GCM.

Implementa:
- ECDHE (P-256) com chaves efêmeras
- Certificado RSA autoassinado (servidor) com persistência em arquivo
- Assinatura RSA do handshake: pk_S || client_id || transcript_hash || salt
- HKDF no estilo TLS 1.3 (Extract + Expand) gerando chaves direcionais:
  Key_c2s = HKDF-Expand(PRK, "c2s", 16)
  Key_s2c = HKDF-Expand(PRK, "s2c", 16)

Observação:
- AES-128-GCM usa chave de 16 bytes (128 bits).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


# =========================
# Helpers de JSON/Base64
# =========================

def b64e(data: bytes) -> str:
    """Base64 (URL-safe) sem quebras de linha."""
    return base64.b64encode(data).decode("utf-8")


def b64d(data_b64: str) -> bytes:
    """Decodifica Base64."""
    return base64.b64decode(data_b64.encode("utf-8"))


def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    """
    Serializa JSON de forma canônica para evitar divergências de transcript.
    - sort_keys=True para ordem determinística
    - separators para remover espaços
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# =========================
# HKDF (RFC5869) - TLS 1.3 style (Extract + Expand)
# =========================

def hkdf_extract(salt: bytes, ikm: bytes, hash_alg=hashlib.sha256) -> bytes:
    """
    HKDF-Extract: PRK = HMAC(salt, IKM)
    No enunciado: PRK = HMAC(salt, Z)
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hash_alg().digest_size
    return hmac.new(salt, ikm, hash_alg).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_alg=hashlib.sha256) -> bytes:
    """
    HKDF-Expand (RFC5869):
    OKM = T(1) || T(2) || ... até atingir 'length'
    T(0) = empty
    T(i) = HMAC(PRK, T(i-1) || info || i)
    """
    digest_len = hash_alg().digest_size
    if length <= 0:
        raise ValueError("HKDF expand length must be > 0")
    if length > 255 * digest_len:
        raise ValueError("HKDF expand length too large")

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hash_alg).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_session_keys(shared_secret_z: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Deriva chaves direcionais AES-128 (16 bytes) a partir do segredo Z e salt.
    Enunciado:
      PRK = HMAC(salt, Z)
      Key_c2s = HKDF-Expand(PRK, "c2s", 16)
      Key_s2c = HKDF-Expand(PRK, "s2c", 16)
    """
    prk = hkdf_extract(salt, shared_secret_z, hashlib.sha256)
    key_c2s = hkdf_expand(prk, b"c2s", 16, hashlib.sha256)
    key_s2c = hkdf_expand(prk, b"s2c", 16, hashlib.sha256)
    return key_c2s, key_s2c


# =========================
# Certificado RSA (Servidor)
# =========================

def generate_or_load_server_certificate(
    cert_path: str = "server_cert.pem",
    key_path: str = "server_key.pem",
    common_name: str = "SecureChatServer",
    rsa_key_size: int = 2048,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Gera ou carrega (do disco) o par:
    - chave privada RSA do servidor
    - certificado X.509 autoassinado do servidor

    IMPORTANTE: persistir em arquivo é essencial para permitir "cert pinning".
    Se o servidor gerar um cert novo a cada execução, o cliente não consegue confiar.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Load key
        priv_pem = open(key_path, "rb").read()
        private_key = serialization.load_pem_private_key(
            priv_pem, password=None, backend=default_backend()
        )
        # Load cert
        cert_pem = open(cert_path, "rb").read()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return private_key, cert

    # Generate new RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_key_size,
        backend=default_backend()
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MultiClientECDHE"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Save
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return private_key, cert


def certificate_fingerprint_sha256(cert: x509.Certificate) -> bytes:
    """Retorna o fingerprint SHA-256 do certificado (bytes)."""
    return cert.fingerprint(hashes.SHA256())


def load_certificate_from_pem(cert_pem: bytes) -> x509.Certificate:
    """Carrega certificado X.509 a partir de bytes PEM."""
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def public_key_from_certificate(cert: x509.Certificate):
    """Extrai a chave pública do certificado."""
    return cert.public_key()


def verify_certificate_pinning(
    received_cert_pem: bytes,
    pinned_cert_path: str = "server_cert.pem"
) -> None:
    """
    Verifica pinagem do certificado:
    - compara fingerprint SHA-256 do cert recebido com o cert local (pinado).
    Lança ValueError se não bater.
    """
    if not os.path.exists(pinned_cert_path):
        raise ValueError(
            f"Certificado pinado não encontrado em '{pinned_cert_path}'. "
            "Você precisa copiar/commitar o server_cert.pem gerado pelo servidor."
        )

    pinned_cert_pem = open(pinned_cert_path, "rb").read()
    pinned_cert = load_certificate_from_pem(pinned_cert_pem)
    received_cert = load_certificate_from_pem(received_cert_pem)

    fp_pinned = certificate_fingerprint_sha256(pinned_cert)
    fp_received = certificate_fingerprint_sha256(received_cert)

    if fp_pinned != fp_received:
        raise ValueError("Falha no cert pinning: certificado do servidor não confere.")


# =========================
# ECDHE + serialização
# =========================

def generate_ecdh_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Gera par efêmero ECDHE (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serializa chave pública ECDHE em PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_pem: bytes) -> ec.EllipticCurvePublicKey:
    """Desserializa chave pública ECDHE (PEM bytes)."""
    return serialization.load_pem_public_key(public_key_pem, backend=default_backend())


def derive_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey
) -> bytes:
    """
    Deriva o segredo compartilhado Z via ECDH:
      Z = ECDH(sk_local, pk_peer)
    """
    return private_key.exchange(ec.ECDH(), peer_public_key)


# =========================
# Transcript + assinatura RSA do handshake
# =========================

def transcript_hash(client_hello_obj: Dict[str, Any], server_hello_obj_without_sig: Dict[str, Any]) -> bytes:
    """
    Gera transcript hash = SHA256( canon(client_hello) || canon(server_hello_sem_assinatura) ).
    Isso reduz ambiguidades e é fácil de reproduzir no servidor e no cliente.
    """
    ch = canonical_json_bytes(client_hello_obj)
    sh = canonical_json_bytes(server_hello_obj_without_sig)
    return hashlib.sha256(ch + sh).digest()


def sign_handshake(
    server_rsa_private_key: rsa.RSAPrivateKey,
    pk_s_pem: bytes,
    client_id_bytes: bytes,
    transcript_digest: bytes,
    salt: bytes
) -> bytes:
    """
    Assina (RSA-PSS/SHA256) o payload:
      pk_S || client_id || transcript_hash || salt
    """
    data = pk_s_pem + client_id_bytes + transcript_digest + salt
    signature = server_rsa_private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature


def verify_handshake_signature(
    server_cert_pem: bytes,
    signature: bytes,
    pk_s_pem: bytes,
    client_id_bytes: bytes,
    transcript_digest: bytes,
    salt: bytes
) -> None:
    """
    Verifica a assinatura do servidor usando a chave pública do certificado.
    Lança ValueError se falhar.
    """
    cert = load_certificate_from_pem(server_cert_pem)
    pub = public_key_from_certificate(cert)

    data = pk_s_pem + client_id_bytes + transcript_digest + salt
    try:
        pub.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception as e:
        raise ValueError(f"Assinatura RSA inválida no handshake: {e}") from e


# =========================
# API alto nível (usada pelo client/server)
# =========================

@dataclass
class HandshakeResult:
    """Resultado do handshake para ser armazenado na sessão."""
    key_c2s: bytes
    key_s2c: bytes
    salt: bytes


def build_client_hello(client_id: str, pk_c_pem: bytes) -> Dict[str, Any]:
    """Monta o objeto JSON do ClientHello."""
    return {
        "type": "client_hello",
        "client_id": client_id,
        "pk_c": b64e(pk_c_pem),
    }


def build_server_hello_without_sig(pk_s_pem: bytes, cert_pem: bytes, salt: bytes) -> Dict[str, Any]:
    """Monta o objeto JSON do ServerHello (sem assinatura)."""
    return {
        "type": "server_hello",
        "pk_s": b64e(pk_s_pem),
        "cert": b64e(cert_pem),
        "salt": b64e(salt),
    }


def finalize_server_hello(server_hello_wo_sig: Dict[str, Any], signature: bytes) -> Dict[str, Any]:
    """Adiciona assinatura ao ServerHello."""
    out = dict(server_hello_wo_sig)
    out["signature"] = b64e(signature)
    return out


def client_process_server_hello(
    client_hello_obj: Dict[str, Any],
    server_hello_obj: Dict[str, Any],
    pinned_cert_path: str = "server_cert.pem"
) -> Tuple[bytes, bytes, bytes, ec.EllipticCurvePublicKey]:
    """
    Lado do cliente: valida cert pinado, valida assinatura e devolve:
    - key_c2s, key_s2c, salt e pk_s (objeto)
    """
    # Extrai campos do server_hello
    cert_pem = b64d(server_hello_obj["cert"])
    pk_s_pem = b64d(server_hello_obj["pk_s"])
    salt = b64d(server_hello_obj["salt"])
    signature = b64d(server_hello_obj["signature"])

    # Cert pinning
    verify_certificate_pinning(cert_pem, pinned_cert_path=pinned_cert_path)

    # Transcript: server_hello sem assinatura
    server_hello_wo_sig = dict(server_hello_obj)
    server_hello_wo_sig.pop("signature", None)
    t_hash = transcript_hash(client_hello_obj, server_hello_wo_sig)

    # client_id bytes (compatível com repo atual que usa uuid string)
    client_id_bytes = client_hello_obj["client_id"].encode("utf-8")

    # Verifica assinatura RSA
    verify_handshake_signature(
        server_cert_pem=cert_pem,
        signature=signature,
        pk_s_pem=pk_s_pem,
        client_id_bytes=client_id_bytes,
        transcript_digest=t_hash,
        salt=salt
    )

    # Decodifica pk_s para uso no ECDH
    pk_s = deserialize_public_key(pk_s_pem)

    # Derivação de chaves será feita após o cliente calcular Z
    return pk_s_pem, cert_pem, salt, pk_s


def server_make_handshake_material(
    client_hello_obj: Dict[str, Any],
    server_priv_rsa: rsa.RSAPrivateKey,
    server_cert: x509.Certificate,
    pk_s_pem: bytes,
    salt: bytes
) -> Dict[str, Any]:
    """
    Lado do servidor: monta o ServerHello assinado (JSON completo).
    """
    cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)

    # server_hello sem assinatura
    server_hello_wo_sig = build_server_hello_without_sig(pk_s_pem=pk_s_pem, cert_pem=cert_pem, salt=salt)

    # transcript hash
    t_hash = transcript_hash(client_hello_obj, server_hello_wo_sig)
    client_id_bytes = client_hello_obj["client_id"].encode("utf-8")

    # assinatura
    sig = sign_handshake(
        server_rsa_private_key=server_priv_rsa,
        pk_s_pem=pk_s_pem,
        client_id_bytes=client_id_bytes,
        transcript_digest=t_hash,
        salt=salt
    )

    return finalize_server_hello(server_hello_wo_sig, sig)
