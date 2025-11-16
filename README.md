# End-to-End Encrypted Messaging System

A simple terminal-based chat system using Diffie-Hellman key exchange and AES-GCM encryption.

## Features

- **End-to-End Encryption**: Messages are encrypted on the client side and can only be decrypted by the intended recipient
- **Diffie-Hellman Key Exchange**: Secure key agreement without transmitting the key over the network
- **AES-GCM Encryption**: Authenticated encryption for message confidentiality and integrity
- **Relay Server**: Server forwards encrypted messages without being able to decrypt them
- **Session-Based**: Create or join sessions using unique session IDs

## Requirements

- Python 3.7+
- pycryptodome

## Installation

1. Install the required dependency:
```bash
pip install pycryptodome
```

## Usage

### 1. Start the Relay Server

```bash
python relay_server.py
```

The server will listen on `0.0.0.0:5000` by default. You can specify a custom port:

```bash
python relay_server.py 8080
```

### 2. Start Client 1 (Create Session)

```bash
python client.py
```

- Choose `C` to create a new session
- You'll receive a session ID (e.g., `A3F2B1`)
- Share this session ID with the other person

### 3. Start Client 2 (Join Session)

```bash
python client.py
```

- Choose `J` to join an existing session
- Enter the session ID provided by Client 1
- The key exchange will automatically complete

### 4. Chat!

Once both clients are connected, you can start sending encrypted messages. The messages are:
- Encrypted with AES-GCM on the sender's side
- Forwarded as ciphertext by the server
- Decrypted on the receiver's side

## How It Works

1. **Session Creation**: Client 1 creates a session and gets a unique session ID
2. **Session Join**: Client 2 joins using the session ID
3. **Key Exchange**: 
   - Both clients generate ephemeral Diffie-Hellman keypairs
   - They exchange public keys through the server
   - Each derives the same shared secret independently
   - The shared secret is used to derive an AES-256 key
4. **Encrypted Chat**:
   - Messages are encrypted with AES-GCM before sending
   - Server forwards the ciphertext without decryption
   - Recipient decrypts using the shared AES key

## Security Features

- **2048-bit Diffie-Hellman**: Using RFC 3526 safe prime
- **AES-256-GCM**: Authenticated encryption
- **Ephemeral Keys**: New keys for each session
- **Server Cannot Decrypt**: Server only sees ciphertext

## File Structure

- `crypto_utils.py`: Cryptographic functions (DH, AES-GCM)
- `relay_server.py`: TCP relay server
- `client.py`: Chat client with encryption
- `README.md`: This file

## Example Session

**Terminal 1 (Server):**
```
$ python relay_server.py
[*] Relay server listening on 0.0.0.0:5000
[*] Waiting for clients to connect...
[+] New connection from ('127.0.0.1', 52341)
[+] Created session A3F2B1 for ('127.0.0.1', 52341)
[+] New connection from ('127.0.0.1', 52342)
[+] Client ('127.0.0.1', 52342) joined session A3F2B1
```

**Terminal 2 (Client 1):**
```
$ python client.py
[+] Connected to server at localhost:5000

==================================================
End-to-End Encrypted Chat Client
==================================================

Do you want to (C)reate a new session or (J)oin an existing one? [C/J]: C
[+] Created session: A3F2B1
[*] Share this session ID with the other person to join
[*] Waiting for another person to join...
[*] Performing Diffie-Hellman key exchange...
[+] Key exchange complete! Secure channel established.

==================================================
Secure chat session started!
Type your messages below. Press Ctrl+C to exit.
==================================================

[You]: Hello!
```

**Terminal 3 (Client 2):**
```
$ python client.py
[+] Connected to server at localhost:5000

==================================================
End-to-End Encrypted Chat Client
==================================================

Do you want to (C)reate a new session or (J)oin an existing one? [C/J]: J
Enter session ID: A3F2B1
[+] Joined session: A3F2B1
[*] Performing Diffie-Hellman key exchange...
[+] Key exchange complete! Secure channel established.

==================================================
Secure chat session started!
Type your messages below. Press Ctrl+C to exit.
==================================================

[Them]: Hello!
[You]: Hi there!
```

## Notes

- The server must be running before clients can connect
- Each session supports exactly 2 clients
- Messages are only encrypted after the key exchange is complete
- Press Ctrl+C to exit the chat
