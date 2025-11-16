"""
Relay Server for End-to-End Encrypted Messaging System
This server acts as a relay - it forwards messages between clients but cannot decrypt them.
"""

import socket
import threading
import secrets
import struct
import sys


class Session:
    """Represents a chat session between two clients"""
    
    def __init__(self, session_id):
        self.session_id = session_id
        self.clients = []  # List of (client_socket, address) tuples
        self.lock = threading.Lock()
    
    def add_client(self, client_socket, address):
        """Add a client to the session"""
        with self.lock:
            if len(self.clients) < 2:
                self.clients.append((client_socket, address))
                return True
            return False
    
    def remove_client(self, client_socket):
        """Remove a client from the session"""
        with self.lock:
            self.clients = [(sock, addr) for sock, addr in self.clients if sock != client_socket]
    
    def get_other_client(self, client_socket):
        """Get the other client in the session"""
        with self.lock:
            for sock, addr in self.clients:
                if sock != client_socket:
                    return sock
            return None
    
    def is_full(self):
        """Check if session has 2 clients"""
        with self.lock:
            return len(self.clients) >= 2
    
    def is_empty(self):
        """Check if session has no clients"""
        with self.lock:
            return len(self.clients) == 0


class RelayServer:
    """TCP relay server for encrypted messaging"""
    
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.sessions = {}  # session_id -> Session
        self.sessions_lock = threading.Lock()
        self.server_socket = None
    
    def generate_session_id(self):
        """Generate a unique 6-character session ID"""
        while True:
            session_id = secrets.token_hex(3).upper()  # 6 hex characters
            with self.sessions_lock:
                if session_id not in self.sessions:
                    return session_id
    
    def create_session(self, client_socket, address):
        """Create a new session"""
        session_id = self.generate_session_id()
        session = Session(session_id)
        session.add_client(client_socket, address)
        
        with self.sessions_lock:
            self.sessions[session_id] = session
        
        print(f"[+] Created session {session_id} for {address}")
        return session_id
    
    def join_session(self, session_id, client_socket, address):
        """Join an existing session"""
        with self.sessions_lock:
            session = self.sessions.get(session_id)
            if session and not session.is_full():
                session.add_client(client_socket, address)
                print(f"[+] Client {address} joined session {session_id}")
                # Notify both clients that session is ready
                if session.is_full():
                    for sock, _ in session.clients:
                        self.send_message(sock, b"READY")
                return True
            return False
    
    def send_message(self, client_socket, message):
        """Send a message with length prefix"""
        try:
            # Send 4-byte length prefix + message
            msg_len = struct.pack('!I', len(message))
            client_socket.sendall(msg_len + message)
            return True
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            return False
    
    def receive_message(self, client_socket):
        """Receive a message with length prefix"""
        try:
            # Receive 4-byte length prefix
            length_data = b''
            while len(length_data) < 4:
                chunk = client_socket.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk
            
            msg_len = struct.unpack('!I', length_data)[0]
            
            # Receive the message
            message = b''
            while len(message) < msg_len:
                chunk = client_socket.recv(min(4096, msg_len - len(message)))
                if not chunk:
                    return None
                message += chunk
            
            return message
        except Exception as e:
            print(f"[!] Error receiving message: {e}")
            return None
    
    def handle_client(self, client_socket, address):
        """Handle a client connection"""
        print(f"[+] New connection from {address}")
        session_id = None
        
        try:
            # Receive initial command: CREATE or JOIN:session_id
            command = self.receive_message(client_socket)
            if not command:
                print(f"[!] Client {address} disconnected during handshake")
                return
            
            command_str = command.decode('utf-8')
            
            if command_str == "CREATE":
                # Create new session
                session_id = self.create_session(client_socket, address)
                self.send_message(client_socket, f"SESSION:{session_id}".encode('utf-8'))
            
            elif command_str.startswith("JOIN:"):
                # Join existing session
                session_id = command_str.split(":", 1)[1]
                if self.join_session(session_id, client_socket, address):
                    self.send_message(client_socket, b"JOINED")
                else:
                    self.send_message(client_socket, b"ERROR:Session not found or full")
                    print(f"[!] Client {address} failed to join session {session_id}")
                    return
            else:
                print(f"[!] Invalid command from {address}: {command_str}")
                return
            
            # Forward messages between clients
            while True:
                message = self.receive_message(client_socket)
                if not message:
                    print(f"[!] Client {address} disconnected")
                    break
                
                # Get the other client in the session
                with self.sessions_lock:
                    session = self.sessions.get(session_id)
                    if session:
                        other_client = session.get_other_client(client_socket)
                        if other_client:
                            # Forward the encrypted message
                            if not self.send_message(other_client, message):
                                print(f"[!] Failed to forward message in session {session_id}")
                                break
                        else:
                            print(f"[!] No other client in session {session_id}")
        
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        
        finally:
            # Clean up
            client_socket.close()
            
            # Remove client from session
            if session_id:
                with self.sessions_lock:
                    session = self.sessions.get(session_id)
                    if session:
                        session.remove_client(client_socket)
                        if session.is_empty():
                            del self.sessions[session_id]
                            print(f"[-] Deleted empty session {session_id}")
            
            print(f"[-] Connection closed: {address}")
    
    def start(self):
        """Start the relay server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            print(f"[*] Relay server listening on {self.host}:{self.port}")
            print(f"[*] Waiting for clients to connect...")
            
            while True:
                client_socket, address = self.server_socket.accept()
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
        
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        except Exception as e:
            print(f"[!] Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()


def main():
    """Main function to start the relay server"""
    # Default host and port
    host = '0.0.0.0'
    port = 5000
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    server = RelayServer(host, port)
    server.start()


if __name__ == "__main__":
    main()
