# client.py - Estrutura básica para começar
import asyncio
import json
import uuid
import sys
from dataclasses import dataclass
import config
from crypto_utils import CryptoUtils
from message import MessageHandler

@dataclass
class ChatSession:
    """Sessão ativa do cliente"""
    server_host: str
    server_port: int
    client_id: str
    key_c2s: bytes = None  # Chave para cifrar mensagens para servidor
    key_s2c: bytes = None  # Chave para decifrar mensagens do servidor
    seq_send: int = 0  # Contador de sequência enviado
    seq_recv: int = 0  # Contador de sequência recebido
    salt: bytes = None

class ChatClient:
    def __init__(self):
        self.session = None
        self.reader = None
        self.writer = None
        self.message_handler = MessageHandler()
        self.client_private_key = None
        self.client_public_key = None
        
    async def connect(self, host: str, port: int):
        """Conecta ao servidor e realiza handshake"""
        print(f"Conectando a {host}:{port}...")
        
        # Gera par de chaves do cliente
        self.client_private_key, self.client_public_key = CryptoUtils.generate_ecdh_key_pair()
        
        # Conecta ao servidor
        self.reader, self.writer = await asyncio.open_connection(host, port)
        
        # TODO: Implementar handshake
        # 1. Enviar pk_C para servidor
        # 2. Receber pk_S + certificado + assinatura + salt
        # 3. Validar assinatura e certificado
        # 4. Calcular segredo compartilhado
        # 5. Derivar chaves
        
        client_id = str(uuid.uuid4())
        self.session = ChatSession(
            server_host=host,
            server_port=port,
            client_id=client_id
        )
        
        print(f"Conectado como {client_id}")
        return True
    
    async def send_message(self, recipient_id: str, message: str):
        """Envia mensagem para outro cliente"""
        if not self.session or not self.session.key_c2s:
            print("Não conectado ou handshake incompleto")
            return
        
        # TODO: Implementar cifragem da mensagem
        # 1. Incrementar seq_send
        # 2. Cifrar com AES-GCM usando Key_c2s
        # 3. Enviar frame completo
        
        print(f"Enviando mensagem para {recipient_id}: {message}")
        
    async def receive_messages(self):
        """Recebe mensagens do servidor"""
        try:
            while True:
                data = await self.reader.read(config.BUFFER_SIZE)
                if not data:
                    break
                
                # TODO: Processar mensagem recebida
                # 1. Decifrar com Key_s2c
                # 2. Validar seq_no
                # 3. Exibir mensagem
                
                print(f"Mensagem recebida: {data}")
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Erro ao receber mensagens: {e}")
    
    async def chat_loop(self):
        """Loop principal do chat"""
        print("\n=== Secure Chat Client ===")
        print("Comandos:")
        print("  /connect [host] [port] - Conectar ao servidor")
        print("  /msg [destino] [mensagem] - Enviar mensagem")
        print("  /list - Listar clientes conectados")
        print("  /quit - Sair")
        print("===========================\n")
        
        while True:
            try:
                user_input = await asyncio.get_event_loop().run_in_executor(
                    None, input, "> "
                )
                
                if user_input.lower() == '/quit':
                    break
                    
                elif user_input.startswith('/connect'):
                    parts = user_input.split()
                    host = parts[1] if len(parts) > 1 else config.SERVER_HOST
                    port = int(parts[2]) if len(parts) > 2 else config.SERVER_PORT
                    
                    if await self.connect(host, port):
                        # Inicia tarefa para receber mensagens
                        asyncio.create_task(self.receive_messages())
                        
                elif user_input.startswith('/msg'):
                    parts = user_input.split(maxsplit=2)
                    if len(parts) >= 3:
                        recipient_id = parts[1]
                        message = parts[2]
                        await self.send_message(recipient_id, message)
                    else:
                        print("Uso: /msg [destino] [mensagem]")
                        
                elif user_input == '/list':
                    print("Lista de clientes conectados:")
                    # TODO: Implementar lista de clientes
                    
            except Exception as e:
                print(f"Erro: {e}")
    
    async def cleanup(self):
        """Limpeza ao sair"""
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