# client.py
import asyncio
import struct
import uuid
from dataclasses import dataclass
from typing import Optional

import config

try:
    from crypto_utils import CryptoUtils
except ImportError:
    import crypto_utils as CryptoUtils

from message import MessageHandler, MessageFrame, uuid_16b_to_str


LEN_FMT = "!I"  # uint32 big-endian
LEN_SIZE = 4

# nonce(12) + sender_id(16) + recipient_id(16) + seq_no(8) = 52 bytes
FRAME_HEADER_SIZE = config.NONCE_SIZE + 16 + 16 + 8

# limite com folga pra evitar bloquear frames validos em mensagens maiores
MAX_FRAME_SIZE = FRAME_HEADER_SIZE + config.MAX_MESSAGE_SIZE + 64


@dataclass
class ChatSession:
    """Sessão ativa do cliente."""
    server_host: str
    server_port: int
    client_id: str
    key_c2s: Optional[bytes] = None
    key_s2c: Optional[bytes] = None
    seq_send: int = 0
    seq_recv: int = 0
    salt: Optional[bytes] = None


class ChatClient:
    def __init__(self):
        self.session: Optional[ChatSession] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        self.message_handler = MessageHandler()
        self.recv_task: Optional[asyncio.Task] = None

        self.client_private_key = None
        self.client_public_key = None

    def print_help(self) -> None:
        print("\ncomandos:")
        print("  /help                  - mostrar comandos")
        print("  /connect [host] [port]  - conectar ao servidor")
        print("  /status                - mostrar status da conexao/sessao")
        print("  /whoami                - mostrar seu client_id")
        print("  /msg [destino] [msg]   - enviar mensagem")
        print("  /quit                  - sair\n")

    def print_status(self) -> None:
        connected = (self.reader is not None) and (self.writer is not None)
        print("\nstatus:")
        print(f"  conectado: {connected}")
        if self.session:
            print(f"  servidor: {self.session.server_host}:{self.session.server_port}")
            print(f"  client_id: {self.session.client_id}")
            print(f"  handshake key_c2s: {'ok' if self.session.key_c2s else 'nao'}")
            print(f"  handshake key_s2c: {'ok' if self.session.key_s2c else 'nao'}")
            print(f"  seq_send: {self.session.seq_send}")
            print(f"  seq_recv: {self.session.seq_recv}")
        else:
            print("  sessao: nao criada")
        print("")




    # Framing TCP (len + frame)
    async def send_frame_bytes(self, frame_bytes: bytes) -> None:
        """Envia: [len(4B big-endian)] + [frame_bytes]."""
        if not self.writer:
            raise RuntimeError("writer não inicializado")

        if not isinstance(frame_bytes, (bytes, bytearray)):
            raise ValueError("frame_bytes deve ser bytes")

        n = len(frame_bytes)
        if n <= 0 or n > MAX_FRAME_SIZE:
            raise ValueError(f"Tamanho de frame inválido: {n}")

        self.writer.write(struct.pack(LEN_FMT, n))
        self.writer.write(frame_bytes)
        await self.writer.drain()

    async def read_frame_bytes(self) -> bytes:
        """Lê: [len(4B)] depois lê exatamente len bytes."""
        if not self.reader:
            raise RuntimeError("reader não inicializado")

        try:
            raw_len = await self.reader.readexactly(LEN_SIZE)
        except asyncio.IncompleteReadError:
            return b""

        (n,) = struct.unpack(LEN_FMT, raw_len)
        if n <= 0 or n > MAX_FRAME_SIZE:
            raise ValueError(f"Tamanho de frame recebido inválido: {n}")

        try:
            frame_bytes = await self.reader.readexactly(n)
        except asyncio.IncompleteReadError:
            return b""

        return frame_bytes

    
    # Conexão + Handshake (TODO)
    async def connect(self, host: str, port: int) -> bool:
        """Conecta ao servidor e realiza handshake."""
        print(f"Conectando a {host}:{port}...")

        # client_id precisa existir ANTES do handshake
        client_id = str(uuid.uuid4())
        self.session = ChatSession(
            server_host=host,
            server_port=port,
            client_id=client_id
        )

        # Gera par de chaves ECDHE do cliente (para handshake)
        self.client_private_key, self.client_public_key = CryptoUtils.generate_ecdh_key_pair()

        # Conecta ao servidor
        self.reader, self.writer = await asyncio.open_connection(host, port)

        # TODO: integrar handshake quando o servidor estiver pronto
        # 1) serializar pk do cliente (pk_c_pem)
        # 2) montar/enviar ClientHello (JSON)
        # 3) receber ServerHello (JSON)
        # 4) validar certificado + assinatura
        # 5) calcular Z via ECDH e derivar key_c2s/key_s2c via HKDF
        # 6) salvar as chaves na sessão

        print(f"Conectado como {client_id}")
        return True


    # Envio/recebimento
    async def send_message(self, recipient_id: str, message: str):
        """Envia mensagem para outro cliente"""
        if not self.session or not self.writer:
            print("Não conectado.")
            return
        if not self.session.key_c2s:
            print("Handshake incompleto: key_c2s não definida.")
            return
        
        try:
            uuid.UUID(recipient_id)
        except Exception:
            print("destino invalido: precisa ser um uuid (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            return

        if not message or not message.strip():
            print("mensagem vazia")
            return


        # seq_no monotônico
        self.session.seq_send += 1
        seq_no = self.session.seq_send

        # Cifra e monta frame (MessageHandler converte UUID string -> 16B internamente)
        frame = self.message_handler.encrypt_message(
            plaintext=message,
            key=self.session.key_c2s,
            sender_uuid=self.session.client_id,
            recipient_uuid=recipient_id,
            seq_no=seq_no,
        )

        frame_bytes = frame.to_bytes()
        await self.send_frame_bytes(frame_bytes)

        print(f"[enviado] to={recipient_id} seq={seq_no}")

    async def receive_messages(self):
        """Recebe frames do servidor, valida seq e decifra com key_s2c."""
        if not self.session:
            return

        try:
            while True:
                frame_bytes = await self.read_frame_bytes()
                if not frame_bytes:
                    print("Conexão encerrada pelo servidor.")
                    break

                try:
                    frame = MessageFrame.from_bytes(frame_bytes)
                except Exception as e:
                    print(f"Frame inválido (drop): {e}")
                    continue

                # checar se é para mim
                try:
                    recipient_str = uuid_16b_to_str(frame.recipient_id)
                except Exception:
                    recipient_str = "<invalid>"

                if recipient_str != self.session.client_id:
                    continue

                # Anti-replay (monotônico)
                if not self.message_handler.validate_sequence(frame.seq_no, self.session.seq_recv):
                    print(f"[replay/drop] seq={frame.seq_no} last={self.session.seq_recv}")
                    continue
                self.session.seq_recv = frame.seq_no

                if not self.session.key_s2c:
                    print("Handshake incompleto: key_s2c não definida.")
                    continue

                plaintext = self.message_handler.decrypt_message(frame, self.session.key_s2c)
                if plaintext is None:
                    print("[drop] falha na autenticação/decifragem (GCM tag)")
                    continue

                try:
                    sender_str = uuid_16b_to_str(frame.sender_id)
                except Exception:
                    sender_str = "<invalid>"

                print(f"\n[from {sender_str} seq={frame.seq_no}] {plaintext}\n> ", end="")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Erro ao receber mensagens: {e}")

    # CLI
    async def chat_loop(self):
        print("\n=== Secure Chat Client ===")
        print("Comandos:")
        print("  /connect [host] [port]  - Conectar ao servidor")
        print("  /whoami                - Mostrar seu client_id")
        print("  /msg [destino] [msg]   - Enviar mensagem")
        print("  /quit                  - Sair")
        print("===========================\n")

        while True:
            try:
                user_input = await asyncio.get_event_loop().run_in_executor(None, input, "> ")

                if user_input.lower() == "/quit":
                    break

                if user_input.strip() == "/help":
                    self.print_help()
                    continue

                if user_input.strip() == "/status":
                    self.print_status()
                    continue


                if user_input.startswith("/connect"):
                    parts = user_input.split()
                    host = parts[1] if len(parts) > 1 else config.SERVER_HOST
                    port = int(parts[2]) if len(parts) > 2 else config.SERVER_PORT

                    ok = await self.connect(host, port)
                    if ok:
                        if self.recv_task and not self.recv_task.done():
                            self.recv_task.cancel()
                        self.recv_task = asyncio.create_task(self.receive_messages())
                    continue

                if user_input.strip() == "/whoami":
                    if self.session:
                        print(f"Você é: {self.session.client_id}")
                    else:
                        print("Ainda não conectado.")
                    continue

                if user_input.startswith("/msg"):
                    parts = user_input.split(maxsplit=2)
                    if len(parts) < 3:
                        print("Uso: /msg [destino] [mensagem]")
                        continue
                    recipient_id = parts[1]
                    msg = parts[2]
                    await self.send_message(recipient_id, msg)
                    continue

                if user_input.strip():
                    print("Comando desconhecido. Use /connect, /whoami, /msg, /quit.")

            except Exception as e:
                print(f"Erro: {e}")

    async def cleanup(self):
        if self.recv_task and not self.recv_task.done():
            self.recv_task.cancel()

        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


async def main():
    client = ChatClient()
    try:
        await client.chat_loop()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
