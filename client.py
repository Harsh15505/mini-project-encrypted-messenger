"""
Client for End-to-End Encrypted Messaging System
Connects to relay server, performs Diffie-Hellman key exchange, and sends/receives encrypted messages.
"""

import socket
import threading
import struct
import sys
from crypto_utils import (
    generate_dh_keypair,
    derive_shared_secret,
    derive_aes_key,
    encrypt_message,
    decrypt_message
)


class ChatClient:
    """Encrypted chat client"""
    
    def __init__(self, server_host='localhost', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.aes_key = None
        self.session_id = None
        self.running = False
        self.listener_thread = None
    
    def send_message(self, message):
        """Send a message with length prefix"""
        try:
            # Send 4-byte length prefix + message
            msg_len = struct.pack('!I', len(message))
            self.socket.sendall(msg_len + message)
            return True
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            return False
    
    def receive_message(self):
        """Receive a message with length prefix"""
        try:
            # Receive 4-byte length prefix
            length_data = b''
            while len(length_data) < 4:
                chunk = self.socket.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk
            
            msg_len = struct.unpack('!I', length_data)[0]
            
            # Receive the message
            message = b''
            while len(message) < msg_len:
                chunk = self.socket.recv(min(4096, msg_len - len(message)))
                if not chunk:
                    return None
                message += chunk
            
            return message
        except Exception as e:
            if self.running:
                print(f"[!] Error receiving message: {e}")
            return None
    
    def connect(self):
        """Connect to the relay server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[+] Connected to server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[!] Failed to connect to server: {e}")
            return False
    
    def create_session(self):
        """Create a new chat session"""
        # Send CREATE command
        self.send_message(b"CREATE")
        
        # Receive session ID
        response = self.receive_message()
        if response and response.startswith(b"SESSION:"):
            self.session_id = response.decode('utf-8').split(":", 1)[1]
            print(f"[+] Created session: {self.session_id}")
            print(f"[*] Share this session ID with the other person to join")
            return True
        else:
            print("[!] Failed to create session")
            return False
    
    def join_session(self, session_id):
        """Join an existing chat session"""
        # Send JOIN command
        self.send_message(f"JOIN:{session_id}".encode('utf-8'))
        
        # Receive response
        response = self.receive_message()
        if response == b"JOINED":
            self.session_id = session_id
            print(f"[+] Joined session: {session_id}")
            return True
        else:
            error_msg = response.decode('utf-8') if response else "Unknown error"
            print(f"[!] Failed to join session: {error_msg}")
            return False
    
    def perform_key_exchange(self, is_initiator):
        """Perform Diffie-Hellman key exchange"""
        print("[*] Performing Diffie-Hellman key exchange...")
        
        # Generate our keypair
        private_key, public_key = generate_dh_keypair()
        
        # Convert public key to bytes
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, byteorder='big')
        
        if is_initiator:
            # Initiator sends their public key first
            print("[*] Sending public key...")
            self.send_message(b"DH_KEY:" + public_key_bytes)
            
            # Receive other party's public key
            print("[*] Waiting for other party's public key...")
            response = self.receive_message()
            if not response or not response.startswith(b"DH_KEY:"):
                print("[!] Failed to receive public key")
                return False
            other_public_key_bytes = response[7:]
        else:
            # Joiner receives public key first
            print("[*] Waiting for other party's public key...")
            response = self.receive_message()
            if not response or not response.startswith(b"DH_KEY:"):
                print("[!] Failed to receive public key")
                return False
            other_public_key_bytes = response[7:]
            
            # Send our public key
            print("[*] Sending public key...")
            self.send_message(b"DH_KEY:" + public_key_bytes)
        
        # Convert received bytes to integer
        other_public_key = int.from_bytes(other_public_key_bytes, byteorder='big')
        
        # Derive shared secret
        shared_secret = derive_shared_secret(private_key, other_public_key)
        
        # Derive AES key from shared secret
        self.aes_key = derive_aes_key(shared_secret)
        
        print("[+] Key exchange complete! Secure channel established.")
        return True
    
    def listen_for_messages(self):
        """Background thread to listen for incoming messages"""
        while self.running:
            try:
                message = self.receive_message()
                if not message:
                    if self.running:
                        print("\n[!] Connection lost")
                        self.running = False
                    break
                
                # Decrypt and display the message
                try:
                    plaintext = decrypt_message(message, self.aes_key)
                    print(f"\n[Them]: {plaintext}")
                    print("[You]: ", end='', flush=True)  # Re-prompt for input
                except Exception as e:
                    print(f"\n[!] Failed to decrypt message: {e}")
            
            except Exception as e:
                if self.running:
                    print(f"\n[!] Error in listener: {e}")
                    self.running = False
                break
    
    def start_chat(self):
        """Start the chat session"""
        self.running = True
        
        # Start listener thread
        self.listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listener_thread.start()
        
        print("\n" + "="*50)
        print("Secure chat session started!")
        print("Type your messages below. Press Ctrl+C to exit.")
        print("="*50 + "\n")
        
        try:
            while self.running:
                # Get user input
                message = input("[You]: ")
                
                if not message.strip():
                    continue
                
                # Encrypt the message
                try:
                    encrypted_message = encrypt_message(message, self.aes_key)
                    
                    # Send encrypted message
                    if not self.send_message(encrypted_message):
                        print("[!] Failed to send message")
                        break
                
                except Exception as e:
                    print(f"[!] Failed to encrypt message: {e}")
        
        except KeyboardInterrupt:
            print("\n[*] Exiting chat...")
        except EOFError:
            print("\n[*] Exiting chat...")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
    
    def run(self):
        """Main client logic"""
        # Connect to server
        if not self.connect():
            return
        
        # Ask user to create or join session
        print("\n" + "="*50)
        print("End-to-End Encrypted Chat Client")
        print("="*50)
        choice = input("\nDo you want to (C)reate a new session or (J)oin an existing one? [C/J]: ").strip().upper()
        
        is_initiator = False
        
        if choice == 'C':
            if not self.create_session():
                return
            is_initiator = True
            print("\n[*] Waiting for another person to join...")
        
        elif choice == 'J':
            session_id = input("Enter session ID: ").strip().upper()
            if not self.join_session(session_id):
                return
        
        else:
            print("[!] Invalid choice")
            return
        
        # Wait for READY signal from server
        print("[*] Waiting for session to be ready...")
        ready_msg = self.receive_message()
        if not ready_msg or ready_msg != b"READY":
            print("[!] Failed to receive ready signal from server")
            return
        print("[+] Both clients connected!")
        
        # Perform Diffie-Hellman key exchange
        if not self.perform_key_exchange(is_initiator):
            return
        
        # Start chat
        self.start_chat()


def main():
    """Main function to start the client"""
    # Default server settings
    server_host = 'localhost'
    server_port = 5000
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    
    client = ChatClient(server_host, server_port)
    client.run()


if __name__ == "__main__":
    main()
