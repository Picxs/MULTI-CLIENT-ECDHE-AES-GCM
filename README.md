# 🔐 Secure Multi-Client Chat  
## ECDHE + RSA + HKDF + AES-128-GCM

Aplicação de **mensageria segura multi-cliente via TCP**, com **handshake autenticado**, **sigilo perfeito (forward secrecy)** e **criptografia ponta-a-servidor-ponta**.  
O servidor atua como intermediário confiável, **decifrando, validando e re-cifrando** mensagens para o destinatário correto.

---

## 📦 Requisitos

- **Python 3.10+**

- **Crie o venv**

- python3 -m venv venv

- Dependências do projeto:
  pip install -r requirements.txt

## Rodando a aplicação:

- **Ative o server**
- No terminal: python server.py


- **Crie o primeiro client**
- em outro terminal use: python client.py

- **Crie o segundo client**
- em um terceiro terminal use: python client.py

- após isso copie o ip de outro client e use o /msg ip mensagem




