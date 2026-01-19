# 🔐 Secure Multi-Client Chat  
## ECDHE + RSA + HKDF + AES-128-GCM

Aplicação de **mensageria segura multi-cliente via TCP**, com **handshake autenticado**, **sigilo perfeito (forward secrecy)** e **criptografia ponta-a-servidor-ponta**.  
O servidor atua como intermediário confiável, **decifrando, validando e re-cifrando** mensagens para o destinatário correto.

---

## 📦 Requisitos

- **Python 3.10+**
- Dependências do projeto:
  ```bash
  pip install -r requirements.txt
