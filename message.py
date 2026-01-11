# message.py
import struct
import secrets
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config

@dataclass
class MessageFrame:
    """Estrutura completa da mensagem cifrada"""
    nonce: bytes  # 12 bytes
    sender_id: str  # 36 bytes (UUID)
    recipient_id: str  # 36 bytes (UUID)
    seq_no: int  # 8 bytes
    ciphertext: bytes  # Mensagem cifrada + tag (16 bytes)
    
    def to_bytes(self) -> bytes:
        """Serializa frame para bytes"""
        # Converte strings UUID para bytes
        sender_bytes = self.sender_id.encode('utf-8')
        recipient_bytes = self.recipient_id.encode('utf-8')
        
        # Empacota dados
        return (
            self.nonce +
            sender_bytes +
            recipient_bytes +
            struct.pack('Q', self.seq_no) +
            struct.pack('I', len(self.ciphertext)) +
            self.ciphertext
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MessageFrame':
        """Desserializa frame de bytes"""
        offset = 0
        
        # Lê nonce (12 bytes)
        nonce = data[offset:offset + config.NONCE_SIZE]
        offset += config.NONCE_SIZE
        
        # Lê sender_id (36 bytes)
        sender_id = data[offset:offset + 36].decode('utf-8')
        offset += 36
        
        # Lê recipient_id (36 bytes)
        recipient_id = data[offset:offset + 36].decode('utf-8')
        offset += 36
        
        # Lê seq_no (8 bytes)
        seq_no = struct.unpack('Q', data[offset:offset + 8])[0]
        offset += 8
        
        # Lê tamanho do ciphertext (4 bytes)
        ciphertext_len = struct.unpack('I', data[offset:offset + 4])[0]
        offset += 4
        
        # Lê ciphertext
        ciphertext = data[offset:offset + ciphertext_len]
        
        return cls(
            nonce=nonce,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=seq_no,
            ciphertext=ciphertext
        )

class MessageHandler:
    """Handler para cifragem e decifragem de mensagens"""
    
    def __init__(self):
        self.aes_gcm = AESGCM  # Referência à classe
    
    def encrypt_message(self, 
                       plaintext: str, 
                       key: bytes, 
                       sender_id: str,
                       recipient_id: str,
                       seq_no: int) -> MessageFrame:
        """Cifra mensagem usando AES-GCM"""
        # Gera nonce único
        nonce = secrets.token_bytes(config.NONCE_SIZE)
        
        # Prepara AAD (dados autenticados adicionalmente)
        aad = (
            sender_id.encode('utf-8') +
            recipient_id.encode('utf-8') +
            struct.pack('Q', seq_no)
        )
        
        # Cifra mensagem
        aesgcm = self.aes_gcm(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), aad)
        
        return MessageFrame(
            nonce=nonce,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=seq_no,
            ciphertext=ciphertext
        )
    
    def decrypt_message(self, frame: MessageFrame, key: bytes) -> Optional[str]:
        """Decifra mensagem e valida tag"""
        try:
            # Prepara AAD
            aad = (
                frame.sender_id.encode('utf-8') +
                frame.recipient_id.encode('utf-8') +
                struct.pack('Q', frame.seq_no)
            )
            
            # Decifra mensagem
            aesgcm = self.aes_gcm(key)
            plaintext = aesgcm.decrypt(frame.nonce, frame.ciphertext, aad)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            print(f"Erro ao decifrar mensagem: {e}")
            return None
    
    def validate_sequence(self, received_seq: int, expected_seq: int) -> bool:
        """Valida número de sequência para prevenir replay attacks"""
        # Implementação básica - espera que received_seq seja maior que expected_seq
        return received_seq > expected_seq