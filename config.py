# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Configurações da rede
SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
SERVER_PORT = int(os.getenv('SERVER_PORT', 5000))
BUFFER_SIZE = 4096

# Configurações criptográficas
ECDHE_CURVE = "secp256r1"  # P-256
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 16  # 128 bits para AES-256-GCM
HKDF_SALT_SIZE = 32
NONCE_SIZE = 12  # GCM recomenda 12 bytes

# Estrutura da mensagem (em bytes)
# [nonce(12)][sender_id(36)][recipient_id(36)][seq_no(8)][ciphertext_len(4)][ciphertext+tag(16)]
MAX_MESSAGE_SIZE = 4096