import struct
import secrets
import uuid
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config

ID_LEN = 16                 #16B
NONCE_LEN = config.NONCE_SIZE  #12B
SEQ_FMT = "!Q"              # uint64 big-endian (network order)
HEADER_SIZE = NONCE_LEN + ID_LEN + ID_LEN + 8  # 12 + 16 + 16 + 8 = 52


def uuid_str_to_16b(u: str) -> bytes:
    """Converte UUID string ('xxxxxxxx-....') em 16 bytes."""
    return uuid.UUID(u).bytes


def uuid_16b_to_str(b: bytes) -> str:
    """Converte 16 bytes em UUID string."""
    return str(uuid.UUID(bytes=b))


@dataclass
class MessageFrame:
    """
    
    [nonce(12)] [sender_id(16)] [recipient_id(16)] [seq_no(8)] [ciphertext+tag]
    """
    nonce: bytes
    sender_id: bytes
    recipient_id: bytes
    seq_no: int
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        if len(self.nonce) != NONCE_LEN:
            raise ValueError(f"nonce deve ter {NONCE_LEN} bytes")
        if len(self.sender_id) != ID_LEN:
            raise ValueError("sender_id deve ter 16 bytes")
        if len(self.recipient_id) != ID_LEN:
            raise ValueError("recipient_id deve ter 16 bytes")
        if not (0 <= self.seq_no <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("seq_no deve ser uint64")
        if not isinstance(self.ciphertext, (bytes, bytearray)) or len(self.ciphertext) < 16:
            raise ValueError("ciphertext inválido (mínimo 16 bytes de tag GCM)")
        if len(self.ciphertext) > config.MAX_MESSAGE_SIZE:
            raise ValueError("ciphertext excede MAX_MESSAGE_SIZE")

        return (
            self.nonce +
            self.sender_id +
            self.recipient_id +
            struct.pack(SEQ_FMT, self.seq_no) +
            self.ciphertext
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageFrame":
        if len(data) < HEADER_SIZE + 16:
            raise ValueError("frame truncado")

        nonce = data[0:NONCE_LEN]
        sender_id = data[NONCE_LEN:NONCE_LEN + ID_LEN]
        recipient_id = data[NONCE_LEN + ID_LEN:NONCE_LEN + ID_LEN + ID_LEN]
        seq_no = struct.unpack(SEQ_FMT, data[NONCE_LEN + 2 * ID_LEN:HEADER_SIZE])[0]
        ciphertext = data[HEADER_SIZE:]

        if len(ciphertext) < 16 or len(ciphertext) > config.MAX_MESSAGE_SIZE:
            raise ValueError("ciphertext tamanho inválido")

        return cls(
            nonce=nonce,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=int(seq_no),
            ciphertext=ciphertext
        )


class MessageHandler:
    """Cifra/decifra usando AES-GCM com AAD = sender|recipient|seq."""

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError("key deve ser bytes")
        if len(key) != config.AES_KEY_SIZE:
            raise ValueError(f"key deve ter {config.AES_KEY_SIZE} bytes")

    @staticmethod
    def _aad(sender_id_16b: bytes, recipient_id_16b: bytes, seq_no: int) -> bytes:
        return sender_id_16b + recipient_id_16b + struct.pack(SEQ_FMT, seq_no)

    def encrypt_message(
        self,
        plaintext: str,
        key: bytes,
        sender_uuid: str,
        recipient_uuid: str,
        seq_no: int
    ) -> MessageFrame:
        self._validate_key(key)

        sender_id = uuid_str_to_16b(sender_uuid)
        recipient_id = uuid_str_to_16b(recipient_uuid)

        nonce = secrets.token_bytes(NONCE_LEN)
        aad = self._aad(sender_id, recipient_id, seq_no)

        aesgcm = AESGCM(bytes(key))
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

        return MessageFrame(
            nonce=nonce,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=seq_no,
            ciphertext=ciphertext
        )

    def decrypt_message(self, frame: MessageFrame, key: bytes) -> Optional[str]:
        try:
            self._validate_key(key)
            aad = self._aad(frame.sender_id, frame.recipient_id, frame.seq_no)
            aesgcm = AESGCM(bytes(key))
            pt = aesgcm.decrypt(frame.nonce, frame.ciphertext, aad)
            return pt.decode("utf-8")
        except Exception as e:
            print(f"Erro ao decifrar mensagem: {e}")
            return None

    def validate_sequence(self, received_seq: int, last_seen_seq: int) -> bool:
        """Anti-replay (monotônico): recebido tem que ser maior que o último."""
        return isinstance(received_seq, int) and received_seq > last_seen_seq
