# server.py - Estrutura básica para começar
import asyncio
import json
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, Optional
import config
from crypto_utils import CryptoUtils

@dataclass
class ClientSession:
    """Estrutura para armazenar informações da sessão do cliente"""
    client_id: str
    transport: asyncio.Transport
    public_key: bytes
    key_c2s: bytes  # Chave para decifrar mensagens do cliente
    key_s2c: bytes  # Chave para cifrar mensagens para o cliente
    seq_recv: int = 0  # Contador de sequência recebido
    seq_send: int = 0  # Contador de sequência enviado
    salt: Optional[bytes] = None

class ChatServer:
    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
        self.server_private_key = None
        self.server_certificate = None
        self.server_public_key = None
        
    async def start_server(self):
        """Inicia o servidor TCP"""
        print(f"Servidor iniciando em {config.SERVER_HOST}:{config.SERVER_PORT}")
        
        # Gera certificado do servidor
        self.server_private_key, self.server_certificate = CryptoUtils.generate_rsa_certificate()
        self.server_public_key = self.server_private_key.public_key()
        
        server = await asyncio.start_server(
            self.handle_client,
            config.SERVER_HOST,
            config.SERVER_PORT
        )
        
        async with server:
            await server.serve_forever()
    
    async def handle_client(self, reader, writer):
        """Manipula nova conexão de cliente"""
        client_address = writer.get_extra_info('peername')
        print(f"Nova conexão de {client_address}")
        
        try:
            # TODO: Implementar handshake
            # 1. Receber pk_C do cliente
            # 2. Gerar pk_S e salt
            # 3. Assinar pk_S + salt
            # 4. Enviar certificado + assinatura
            # 5. Derivar chaves
            
            # TODO: Após handshake, entrar no loop de mensagens
            
            while True:
                data = await reader.read(config.BUFFER_SIZE)
                if not data:
                    break
                    
                # TODO: Processar mensagem cifrada
                # 1. Decifrar com Key_c2s
                # 2. Validar seq_no
                # 3. Roteamento para cliente destino
                
        except Exception as e:
            print(f"Erro com cliente {client_address}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            print(f"Conexão fechada: {client_address}")
    
    def add_session(self, client_id: str, session: ClientSession):
        """Adiciona nova sessão de cliente"""
        self.sessions[client_id] = session
    
    def remove_session(self, client_id: str):
        """Remove sessão de cliente"""
        if client_id in self.sessions:
            del self.sessions[client_id]
    
    async def route_message(self, sender_id: str, recipient_id: str, encrypted_message: bytes):
        """Roteia mensagem entre clientes"""
        # TODO: Implementar roteamento
        # 1. Buscar sessão do destinatário
        # 2. Re-cifrar mensagem com Key_s2c do destinatário
        # 3. Enviar para destinatário
        pass

if __name__ == "__main__":
    server = ChatServer()
    asyncio.run(server.start_server())