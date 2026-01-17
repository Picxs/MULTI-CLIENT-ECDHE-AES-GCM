# server.py - Servidor completo para chat seguro
import asyncio
import json
import uuid
import secrets
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, List
from datetime import datetime
import os
from cryptography.hazmat.primitives import serialization

# Importações do nosso projeto
import config
from crypto_utils import (
    generate_or_load_server_certificate,
    generate_ecdh_key_pair,
    serialize_public_key,
    deserialize_public_key,
    derive_shared_secret,
    derive_session_keys,
    build_client_hello,
    server_make_handshake_material,
    b64d,
    canonical_json_bytes,
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
    pk_c: bytes  # Chave pública ECDHE do cliente (PEM)
    pk_s: bytes  # Nossa chave pública ECDHE para este cliente (PEM)
    salt: bytes  # Salt usado no HKDF
    seq_recv: int = 0  # Último seq_no recebido DESTE cliente
    seq_send: int = 0  # Último seq_no enviado PARA este cliente
    connected_at: datetime = field(default_factory=datetime.now)
    message_handler: MessageHandler = field(default_factory=MessageHandler)
    
    def get_next_seq_send(self) -> int:
        """Retorna próximo seq_no para enviar ao cliente"""
        self.seq_send += 1
        return self.seq_send
    
    def validate_seq_recv(self, seq_no: int) -> bool:
        """Valida seq_no recebido para prevenir replay attacks"""
        # Seq_no deve ser maior que o último recebido
        if seq_no <= self.seq_recv:
            print(f"[REPLAY DETECTED] Cliente {self.client_id}: "
                  f"seq_no={seq_no}, último={self.seq_recv}")
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
        
        # Sessões ativas: client_id -> ClientSession
        self.sessions: Dict[str, ClientSession] = {}
        
        # Para broadcast: conjunto de client_ids conectados
        self.connected_clients: Set[str] = set()
        
        # Criptografia do servidor
        self.server_priv_rsa = None
        self.server_cert = None
        self.server_cert_pem = None
        
        # Para estatísticas
        self.stats = {
            'connections': 0,
            'messages_routed': 0,
            'handshakes_failed': 0,
            'replay_attempts': 0,
        }
        
        # Para logs
        self.start_time = datetime.now()
    
    async def start(self):
        """Inicia o servidor"""
        print(f"🚀 Iniciando servidor Secure Chat em {self.host}:{self.port}")
        
        # Carrega certificado RSA do servidor
        print("📄 Carregando certificado do servidor...")
        self.server_priv_rsa, self.server_cert = generate_or_load_server_certificate()
        self.server_cert_pem = self.server_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        )
        print(f"✅ Certificado carregado (SHA256 fingerprint)")
        
        # Inicia servidor TCP
        server = await asyncio.start_server(
            self.handle_client_connection,
            self.host,
            self.port
        )
        
        # Inicia tarefa de manutenção periódica
        asyncio.create_task(self.maintenance_task())
        
        # Interface administrativa local
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
        
        try:
            # 1. REALIZAR HANDSHAKE
            session = await self.perform_handshake(reader, writer, client_addr)
            if not session:
                print(f"❌ Handshake falhou para {connection_id}")
                self.stats['handshakes_failed'] += 1
                return
            
            print(f"✅ Handshake completo com {session.client_id} ({connection_id})")
            
            # 2. NOTIFICAR OUTROS CLIENTES (opcional - apenas para demo)
            await self.notify_client_connected(session.client_id)
            
            # 3. LOOP PRINCIPAL DE MENSAGENS
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
            # 4. LIMPEZA
            await self.cleanup_client(session.client_id if 'session' in locals() else None)
            writer.close()
            await writer.wait_closed()
    
    async def perform_handshake(self, reader, writer, client_addr):
        """
        Executa handshake ECDHE + RSA com o cliente.
        Retorna ClientSession se bem-sucedido, None caso contrário.
        """
        try:
            # 1. RECEBER ClientHello
            data = await reader.read(4096)
            if not data:
                print(f"⚠️  Conexão fechada durante handshake")
                return None
            
            client_hello = json.loads(data.decode('utf-8'))
            
            # Validar estrutura do ClientHello
            if not all(k in client_hello for k in ['type', 'client_id', 'pk_c']):
                print(f"❌ ClientHello inválido de {client_addr}")
                return None
            
            if client_hello['type'] != 'client_hello':
                print(f"❌ Tipo de mensagem inválido: {client_hello.get('type')}")
                return None
            
            client_id = client_hello['client_id']
            
            # Verificar se client_id já está conectado
            if client_id in self.sessions:
                print(f"⚠️  Client_id {client_id} já está conectado. Desconectando anterior...")
                await self.cleanup_client(client_id)
            
            print(f"🤝 Handshake iniciado com {client_id}")
            
            # 2. EXTRAIR pk_c do cliente
            pk_c_pem = b64d(client_hello['pk_c'])
            pk_c = deserialize_public_key(pk_c_pem)
            
            # 3. GERAR nossas chaves ECDHE e salt
            sk_s, pk_s = generate_ecdh_key_pair()
            pk_s_pem = serialize_public_key(pk_s)
            salt = secrets.token_bytes(32)
            
            # 4. CRIAR ServerHello assinado
            server_hello = server_make_handshake_material(
                client_hello_obj=client_hello,
                server_priv_rsa=self.server_priv_rsa,
                server_cert=self.server_cert,
                pk_s_pem=pk_s_pem,
                salt=salt
            )
            
            # 5. ENVIAR ServerHello para o cliente
            writer.write(json.dumps(server_hello).encode('utf-8'))
            await writer.drain()
            
            # 6. CALCULAR segredo compartilhado e derivar chaves
            shared_secret = derive_shared_secret(sk_s, pk_c)
            key_c2s, key_s2c = derive_session_keys(shared_secret, salt)
            
            # 7. CRIAR sessão do cliente
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
            
            # 8. REGISTRAR sessão
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
                # Ler tamanho do frame (primeiros 4 bytes)
                header = await session.reader.readexactly(4)
                if not header:
                    break
                    
                # Decodificar tamanho do frame
                frame_len = struct.unpack('!I', header)[0]
                
                # Verificar tamanho máximo
                if frame_len > config.MAX_MESSAGE_SIZE:
                    print(f"⚠️  Frame muito grande de {session.client_id}: {frame_len} bytes")
                    break
                
                # Ler o restante do frame
                frame_data = await session.reader.readexactly(frame_len)
                
                # Processar mensagem
                await self.process_message(session, frame_data)
                
            except asyncio.IncompleteReadError:
                print(f"📤 Cliente {session.client_id} desconectou (incomplete read)")
                break
            except ConnectionError:
                print(f"📤 Cliente {session.client_id} desconectou (connection error)")
                break
            except Exception as e:
                print(f"💥 Erro no loop de mensagens de {session.client_id}: {e}")
                break
    
    async def process_message(self, sender_session: ClientSession, frame_data: bytes):
        """Processa uma mensagem recebida de um cliente"""
        try:
            # 1. DECODIFICAR frame
            frame = MessageFrame.from_bytes(frame_data)
            
            # 2. VALIDAR sender_id
            if frame.sender_id != sender_session.client_id:
                print(f"⚠️  sender_id não corresponde: esperado {sender_session.client_id}, "
                      f"recebido {frame.sender_id}")
                return
            
            # 3. VALIDAR seq_no (replay protection)
            if not sender_session.validate_seq_recv(frame.seq_no):
                self.stats['replay_attempts'] += 1
                print(f"🚫 Replay detectado de {sender_session.client_id}, seq={frame.seq_no}")
                return
            
            # 4. DECIFRAR mensagem (usando key_c2s do remetente)
            plaintext = sender_session.message_handler.decrypt_message(frame, sender_session.key_c2s)
            if not plaintext:
                print(f"❌ Falha ao decifrar mensagem de {sender_session.client_id}")
                return
            
            print(f"📩 [{sender_session.client_id} → {frame.recipient_id}] {plaintext}")
            
            # 5. ROTEAMENTO
            # 5a. Mensagem para todos (broadcast)
            if frame.recipient_id == "ALL":
                await self.broadcast_message(sender_session, plaintext, frame.seq_no)
            
            # 5b. Mensagem para servidor (comando)
            elif frame.recipient_id == "SERVER":
                await self.handle_server_command(sender_session, plaintext)
            
            # 5c. Mensagem para cliente específico
            else:
                await self.route_to_client(
                    sender_session.client_id,
                    frame.recipient_id,
                    plaintext,
                    frame.seq_no
                )
            
            self.stats['messages_routed'] += 1
            
        except Exception as e:
            print(f"💥 Erro processando mensagem: {e}")
            import traceback
            traceback.print_exc()
    
    async def route_to_client(self, sender_id: str, recipient_id: str, plaintext: str, seq_no: int):
        """Roteia mensagem para um cliente específico"""
        # 1. VERIFICAR se destinatário existe
        if recipient_id not in self.sessions:
            print(f"⚠️  Destinatário {recipient_id} não encontrado")
            
            # Opcional: notificar remetente que destinatário não está disponível
            # await self.send_error_notification(sender_id, f"Cliente {recipient_id} não está conectado")
            return
        
        recipient_session = self.sessions[recipient_id]
        
        # 2. CIFRAR mensagem para o destinatário (usando key_s2c do destinatário)
        new_frame = recipient_session.message_handler.encrypt_message(
            plaintext=plaintext,
            key=recipient_session.key_s2c,
            sender_id=sender_id,
            recipient_id=recipient_id,
            seq_no=recipient_session.get_next_seq_send()
        )
        
        # 3. ENVIAR para destinatário
        await self.send_frame(recipient_session, new_frame)
        
        print(f"📤 [{sender_id} → {recipient_id}] Mensagem roteada")
    
    async def broadcast_message(self, sender_session: ClientSession, plaintext: str, seq_no: int):
        """Envia mensagem para todos os clientes conectados (exceto remetente)"""
        print(f"📢 Broadcast de {sender_session.client_id}: {plaintext}")
        
        for client_id, recipient_session in self.sessions.items():
            if client_id == sender_session.client_id:
                continue  # Pular remetente
            
            # Cifrar para cada destinatário
            frame = recipient_session.message_handler.encrypt_message(
                plaintext=plaintext,
                key=recipient_session.key_s2c,
                sender_id=sender_session.client_id,
                recipient_id=client_id,
                seq_no=recipient_session.get_next_seq_send()
            )
            
            await self.send_frame(recipient_session, frame)
    
    async def handle_server_command(self, sender_session: ClientSession, command: str):
        """Processa comandos enviados ao servidor"""
        print(f"⚙️  Comando de {sender_session.client_id}: {command}")
        
        if command.strip() == "/list":
            # Enviar lista de clientes conectados
            client_list = "\n".join([f"• {cid}" for cid in self.connected_clients])
            response = f"📋 Clientes conectados ({len(self.connected_clients)}):\n{client_list}"
            
            # Enviar resposta como mensagem normal
            frame = sender_session.message_handler.encrypt_message(
                plaintext=response,
                key=sender_session.key_s2c,
                sender_id="SERVER",
                recipient_id=sender_session.client_id,
                seq_no=sender_session.get_next_seq_send()
            )
            
            await self.send_frame(sender_session, frame)
    
    async def send_frame(self, session: ClientSession, frame: MessageFrame):
        """Envia um frame para um cliente"""
        try:
            # Converter frame para bytes
            frame_bytes = frame.to_bytes()
            
            # Enviar tamanho (4 bytes) + frame
            size_header = struct.pack('!I', len(frame_bytes))
            session.writer.write(size_header + frame_bytes)
            await session.writer.drain()
        except (ConnectionError, BrokenPipeError):
            print(f"⚠️  Não foi possível enviar para {session.client_id} (desconectado)")
            await self.cleanup_client(session.client_id)
    
    async def notify_client_connected(self, new_client_id: str):
        """Notifica outros clientes sobre nova conexão (opcional)"""
        notification = f"🆕 {new_client_id} entrou no chat"
        
        for client_id, session in self.sessions.items():
            if client_id == new_client_id:
                continue
            
            frame = session.message_handler.encrypt_message(
                plaintext=notification,
                key=session.key_s2c,
                sender_id="SERVER",
                recipient_id=client_id,
                seq_no=session.get_next_seq_send()
            )
            
            await self.send_frame(session, frame)
    
    async def cleanup_client(self, client_id: str):
        """Remove cliente desconectado"""
        if client_id in self.sessions:
            session = self.sessions.pop(client_id)
            self.connected_clients.discard(client_id)
            
            # Notificar outros clientes (opcional)
            notification = f"👋 {client_id} saiu do chat"
            for other_id, other_session in self.sessions.items():
                frame = other_session.message_handler.encrypt_message(
                    plaintext=notification,
                    key=other_session.key_s2c,
                    sender_id="SERVER",
                    recipient_id=other_id,
                    seq_no=other_session.get_next_seq_send()
                )
                await self.send_frame(other_session, frame)
            
            print(f"🗑️  Sessão de {client_id} removida")
    
    # =========================
    # Tarefas Auxiliares
    # =========================
    
    async def maintenance_task(self):
        """Tarefa periódica de manutenção do servidor"""
        while True:
            await asyncio.sleep(60)  # Executar a cada 60 segundos
            
            # Remover sessões inativas (timeout de 5 minutos)
            current_time = datetime.now()
            inactive_clients = []
            
            for client_id, session in self.sessions.items():
                time_diff = (current_time - session.connected_at).total_seconds()
                if time_diff > 300:  # 5 minutos
                    inactive_clients.append(client_id)
            
            for client_id in inactive_clients:
                print(f"⏰ Removendo cliente inativo: {client_id}")
                await self.cleanup_client(client_id)
    
    async def admin_interface(self):
        """Interface administrativa local para o servidor"""
        while True:
            try:
                # Ler comando do terminal
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
                    # Desconectar todos os clientes
                    for client_id in list(self.sessions.keys()):
                        await self.cleanup_client(client_id)
                    print("👋 Servidor encerrado")
                    os._exit(0)
                    
                elif cmd.strip():
                    print(f"Comando desconhecido: {cmd}")
                    
            except (EOFError, KeyboardInterrupt):
                print("\n🛑 Comando Ctrl+C detectado. Use /quit para encerrar corretamente.")
            except Exception as e:
                print(f"💥 Erro no comando administrativo: {e}")

# =========================
# Inicialização
# =========================

if __name__ == "__main__":
    print("=" * 50)
    print("🤝 SERVIDOR DE CHAT SEGURO")
    print("  ECDHE + RSA + AES-GCM + cert pinning")
    print("=" * 50)
    
    import sys
    
    # Verificar se foi passado host e porta como argumentos
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