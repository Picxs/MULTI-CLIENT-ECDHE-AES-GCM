# server.py - Servidor completo para chat seguro
import asyncio
import json
import uuid
import secrets
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Set
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization

import config
from crypto_utils import (
    generate_or_load_server_certificate,
    generate_ecdh_key_pair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_secret,
    derive_session_keys,
    server_make_handshake_material,
    b64d,
)
from message import MessageFrame, MessageHandler


# =========================
# Estruturas de Dados
# =========================

@dataclass
class ClientSession:
    """Sessão ativa de um cliente conectado"""
    client_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    address: tuple
    key_c2s: bytes  # Chave para decifrar mensagens DESTE cliente
    key_s2c: bytes  # Chave para cifrar mensagens PARA este cliente
    pk_c: bytes     # Chave pública ECDHE do cliente (PEM)
    pk_s: bytes     # Nossa chave pública ECDHE para este cliente (PEM)
    salt: bytes     # Salt usado no HKDF
    seq_recv: int = 0
    seq_send: int = 0
    connected_at: datetime = field(default_factory=datetime.now)
    message_handler: MessageHandler = field(default_factory=MessageHandler)

    def get_next_seq_send(self) -> int:
        """Retorna próximo seq_no para enviar ao cliente"""
        self.seq_send += 1
        return self.seq_send

    def validate_seq_recv(self, seq_no: int) -> bool:
        """Valida seq_no recebido para prevenir replay attacks"""
        if seq_no <= self.seq_recv:
            print(f"[REPLAY DETECTED] Cliente {self.client_id}: seq_no={seq_no}, último={self.seq_recv}")
            return False
        self.seq_recv = seq_no
        return True


# =========================
# Servidor Principal
# =========================

class ChatServer:
    def __init__(self, host: str = None, port: int = None):
        self.host = host or config.SERVER_HOST
        self.port = port or config.SERVER_PORT

        self.sessions: Dict[str, ClientSession] = {}
        self.connected_clients: Set[str] = set()

        self.server_priv_rsa = None
        self.server_cert = None
        self.server_cert_pem = None

        self.stats = {
            'connections': 0,
            'messages_routed': 0,
            'handshakes_failed': 0,
            'replay_attempts': 0,
        }

        self.start_time = datetime.now()

    async def start(self):
        """Inicia o servidor"""
        print(f"🚀 Iniciando servidor Secure Chat em {self.host}:{self.port}")

        print("📄 Carregando certificado do servidor...")
        self.server_priv_rsa, self.server_cert = generate_or_load_server_certificate()
        self.server_cert_pem = self.server_cert.public_bytes(encoding=serialization.Encoding.PEM)
        print(f"✅ Certificado carregado (SHA256 fingerprint)")

        server = await asyncio.start_server(
            self.handle_client_connection,
            self.host,
            self.port
        )

        asyncio.create_task(self.maintenance_task())
        asyncio.create_task(self.admin_interface())

        print(f"📡 Servidor ouvindo em {self.host}:{self.port}")
        print(f"📊 Comandos administrativos: /stats, /clients, /help")

        async with server:
            await server.serve_forever()

    async def handle_client_connection(self, reader, writer):
        """Manipula nova conexão de cliente"""
        client_addr = writer.get_extra_info('peername')
        connection_id = f"{client_addr[0]}:{client_addr[1]}"

        print(f"🔗 Nova conexão de {connection_id}")
        self.stats['connections'] += 1

        session = None
        try:
            session = await self.perform_handshake(reader, writer, client_addr)
            if not session:
                print(f"❌ Handshake falhou para {connection_id}")
                self.stats['handshakes_failed'] += 1
                return

            print(f"✅ Handshake completo com {session.client_id} ({connection_id})")

            # IMPORTANTE: Removemos notificações SERVER/ALL (não são exigidas e quebravam UUID)
            await self.message_loop(session)

        except (ConnectionError, asyncio.IncompleteReadError):
            print(f"📤 Cliente {connection_id} desconectou")
        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido de {connection_id}: {e}")
        except Exception as e:
            print(f"💥 Erro com cliente {connection_id}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if session is not None:
                await self.cleanup_client(session.client_id)
            writer.close()
            await writer.wait_closed()

    async def perform_handshake(self, reader, writer, client_addr):
        """
        Executa handshake ECDHE + RSA com o cliente.
        Retorna ClientSession se bem-sucedido, None caso contrário.
        """
        try:
            # Receber ClientHello (JSON)
            data = await reader.read(4096)
            if not data:
                print(f"⚠️  Conexão fechada durante handshake")
                return None

            client_hello = json.loads(data.decode('utf-8'))

            if not all(k in client_hello for k in ['type', 'client_id', 'pk_c']):
                print(f"❌ ClientHello inválido de {client_addr}")
                return None

            if client_hello['type'] != 'client_hello':
                print(f"❌ Tipo de mensagem inválido: {client_hello.get('type')}")
                return None

            client_id = client_hello['client_id']

            # Validar que é um UUID válido (evita strings estranhas)
            try:
                uuid.UUID(client_id)
            except Exception:
                print(f"❌ client_id não é UUID válido: {client_id}")
                return None

            if client_id in self.sessions:
                print(f"⚠️  Client_id {client_id} já está conectado. Desconectando anterior...")
                await self.cleanup_client(client_id)

            print(f"🤝 Handshake iniciado com {client_id}")

            pk_c_pem = b64d(client_hello['pk_c'])
            pk_c = deserialize_public_key(pk_c_pem)

            sk_s, pk_s = generate_ecdh_key_pair()
            pk_s_pem = serialize_public_key(pk_s)
            salt = secrets.token_bytes(32)

            server_hello = server_make_handshake_material(
                client_hello_obj=client_hello,
                server_priv_rsa=self.server_priv_rsa,
                server_cert=self.server_cert,
                pk_s_pem=pk_s_pem,
                salt=salt
            )

            # Envia ServerHello (JSON)
            writer.write(json.dumps(server_hello).encode('utf-8'))
            await writer.drain()

            shared_secret = derive_shared_secret(sk_s, pk_c)
            key_c2s, key_s2c = derive_session_keys(shared_secret, salt)

            session = ClientSession(
                client_id=client_id,
                reader=reader,
                writer=writer,
                address=client_addr,
                key_c2s=key_c2s,
                key_s2c=key_s2c,
                pk_c=pk_c_pem,
                pk_s=pk_s_pem,
                salt=salt
            )

            self.sessions[client_id] = session
            self.connected_clients.add(client_id)

            return session

        except Exception as e:
            print(f"❌ Erro durante handshake: {e}")
            import traceback
            traceback.print_exc()
            return None

    async def message_loop(self, session: ClientSession):
        """Loop principal de recebimento de mensagens do cliente"""
        print(f"📨 Iniciando loop de mensagens para {session.client_id}")

        while True:
            try:
                header = await session.reader.readexactly(4)
                if not header:
                    break

                frame_len = struct.unpack('!I', header)[0]

                if frame_len > config.MAX_MESSAGE_SIZE:
                    print(f"⚠️  Frame muito grande de {session.client_id}: {frame_len} bytes")
                    break

                frame_data = await session.reader.readexactly(frame_len)
                await self.process_message(session, frame_data)

            except asyncio.IncompleteReadError:
                print(f"📤 Cliente {session.client_id} desconectou")
                break
            except ConnectionError:
                print(f"📤 Cliente {session.client_id} desconectou")
                break
            except Exception as e:
                print(f"💥 Erro no loop de mensagens de {session.client_id}: {e}")
                import traceback
                traceback.print_exc()
                break

    async def process_message(self, sender_session: ClientSession, frame_data: bytes):
        """Processa uma mensagem recebida de um cliente"""
        try:
            frame = MessageFrame.from_bytes(frame_data)

            # frame.sender_id é 16 bytes (UUID bytes). sender_session.client_id é string.
            expected_sender_16b = uuid.UUID(sender_session.client_id).bytes
            if frame.sender_id != expected_sender_16b:
                print(f"⚠️  sender_id não corresponde (frame != sessão) para {sender_session.client_id}")
                return

            if not sender_session.validate_seq_recv(frame.seq_no):
                self.stats['replay_attempts'] += 1
                print(f"🚫 Replay detectado de {sender_session.client_id}, seq={frame.seq_no}")
                return

            plaintext = sender_session.message_handler.decrypt_message(frame, sender_session.key_c2s)
            if plaintext is None:
                print(f"❌ Falha ao decifrar mensagem de {sender_session.client_id}")
                return

            recipient_uuid_str = str(uuid.UUID(bytes=frame.recipient_id))
            print(f"📩 [{sender_session.client_id} → {recipient_uuid_str}] {plaintext}")

            await self.route_to_client(
                sender_id=sender_session.client_id,
                recipient_id=recipient_uuid_str,
                plaintext=plaintext
            )

            self.stats['messages_routed'] += 1

        except Exception as e:
            print(f"💥 Erro processando mensagem: {e}")
            import traceback
            traceback.print_exc()

    async def route_to_client(self, sender_id: str, recipient_id: str, plaintext: str):
        """Roteia mensagem para um cliente específico"""
        if recipient_id not in self.sessions:
            print(f"⚠️  Destinatário {recipient_id} não encontrado (não conectado)")
            return

        recipient_session = self.sessions[recipient_id]

        new_frame = recipient_session.message_handler.encrypt_message(
            plaintext=plaintext,
            key=recipient_session.key_s2c,
            sender_uuid=sender_id,
            recipient_uuid=recipient_id,
            seq_no=recipient_session.get_next_seq_send()
        )

        await self.send_frame(recipient_session, new_frame)
        print(f"📤 [{sender_id} → {recipient_id}] Mensagem roteada")

    async def send_frame(self, session: ClientSession, frame: MessageFrame):
        """Envia um frame para um cliente"""
        try:
            frame_bytes = frame.to_bytes()
            size_header = struct.pack('!I', len(frame_bytes))
            session.writer.write(size_header + frame_bytes)
            await session.writer.drain()
        except (ConnectionError, BrokenPipeError):
            print(f"⚠️  Não foi possível enviar para {session.client_id} (desconectado)")
            await self.cleanup_client(session.client_id)

    async def cleanup_client(self, client_id: str):
        """Remove cliente desconectado"""
        if client_id in self.sessions:
            self.sessions.pop(client_id, None)
            self.connected_clients.discard(client_id)
            print(f"🗑️  Sessão de {client_id} removida")

    # =========================
    # Tarefas Auxiliares
    # =========================

    async def maintenance_task(self):
        """Tarefa periódica de manutenção do servidor"""
        while True:
            await asyncio.sleep(60)

            current_time = datetime.now()
            inactive_clients = []

            for client_id, session in list(self.sessions.items()):
                time_diff = (current_time - session.connected_at).total_seconds()
                if time_diff > 300:
                    inactive_clients.append(client_id)

            for client_id in inactive_clients:
                print(f"⏰ Removendo cliente inativo: {client_id}")
                await self.cleanup_client(client_id)

    async def admin_interface(self):
        """Interface administrativa local para o servidor"""
        while True:
            try:
                cmd = await asyncio.get_event_loop().run_in_executor(None, input, "server> ")

                if cmd == "/stats":
                    uptime = datetime.now() - self.start_time
                    print(f"\n📊 ESTATÍSTICAS DO SERVIDOR")
                    print(f"  Tempo ativo: {uptime}")
                    print(f"  Conexões totais: {self.stats['connections']}")
                    print(f"  Clientes conectados: {len(self.connected_clients)}")
                    print(f"  Mensagens roteadas: {self.stats['messages_routed']}")
                    print(f"  Handshakes falhos: {self.stats['handshakes_failed']}")
                    print(f"  Tentativas de replay: {self.stats['replay_attempts']}")

                elif cmd == "/clients":
                    print(f"\n📋 CLIENTES CONECTADOS ({len(self.connected_clients)})")
                    for client_id in self.connected_clients:
                        session = self.sessions.get(client_id)
                        if session:
                            conn_time = datetime.now() - session.connected_at
                            print(f"  • {client_id} - {session.address[0]}:{session.address[1]} "
                                  f"(conectado há {int(conn_time.total_seconds())}s)")

                elif cmd == "/help":
                    print("\n🛠️  COMANDOS DO SERVIDOR")
                    print("  /stats     - Mostrar estatísticas")
                    print("  /clients   - Listar clientes conectados")
                    print("  /help      - Mostrar esta ajuda")
                    print("  /quit      - Encerrar servidor")

                elif cmd == "/quit":
                    print("🛑 Encerrando servidor...")
                    for client_id in list(self.sessions.keys()):
                        await self.cleanup_client(client_id)
                    print("👋 Servidor encerrado")
                    os._exit(0)

                elif cmd.strip():
                    print(f"Comando desconhecido: {cmd}")

            except (EOFError, KeyboardInterrupt):
                print("\n🛑 Ctrl+C detectado. Use /quit para encerrar corretamente.")
            except Exception as e:
                print(f"💥 Erro no comando administrativo: {e}")


if __name__ == "__main__":
    print("=" * 50)
    print("🤝 SERVIDOR DE CHAT SEGURO")
    print("  ECDHE + RSA + AES-GCM + cert pinning")
    print("=" * 50)

    import sys
    host = None
    port = None

    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    server = ChatServer(host, port)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n🛑 Servidor interrompido pelo usuário")
    except Exception as e:
        print(f"💥 Erro fatal: {e}")
        import traceback
        traceback.print_exc()
