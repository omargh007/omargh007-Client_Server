#done by Omar
# connection_manager.py
import socket
import threading
import logging
import time
import uuid
from django.conf import settings

# Constants
IP = "127.0.0.1"
PORT = 4456
ADDR = (IP, PORT)
SIZE = 1024
MESSAGE_DELIMITER = b"\r\n"

class TimeoutSocket:
    def __init__(self, sock, timeout_seconds=30):
        self.sock = sock
        self.timeout_seconds = timeout_seconds
        self.buffer = b""
        self.sock.settimeout(timeout_seconds)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.sock.sendall(data + MESSAGE_DELIMITER)

    def recv(self, size):
        while True:
            if MESSAGE_DELIMITER in self.buffer:
                message, self.buffer = self.buffer.split(MESSAGE_DELIMITER, 1)
                return message
            data = self.sock.recv(size)
            if not data:
                break
            self.buffer += data
        return b""

class UserConnection:
    """A connection for a specific user session"""
    
    def __init__(self):
        self.client = None
        self.connection_alive = False
        self.last_activity = 0
        self.activity_timeout = 600  # 2 minutes timeout
        self.connect_lock = threading.Lock()
        
    def connect(self):
        with self.connect_lock:
            if self.is_connected():
                return self.client
                
            try:
                logging.info("Establishing new server connection...")
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_sock.connect(ADDR)
                self.client = TimeoutSocket(client_sock)
                welcome_msg = self.client.recv(SIZE)
                logging.info(f"Connected to server. Welcome message: {welcome_msg}")
                self.connection_alive = True
                self.update_activity()
                return self.client
            except Exception as e:
                logging.error(f"Connection failed: {e}")
                self.connection_alive = False
                return None
    
    def get_connection(self):
        if not self.is_connected():
            return self.connect()
        self.update_activity()
        return self.client
    
    def is_connected(self):
        if not self.connection_alive or not self.client:
            return False
            
        # Check if socket is still valid
        try:
            return self.connection_alive
        except Exception:
            self.connection_alive = False
            return False
            
    def disconnect(self):
        with self.connect_lock:
            if self.client:
                try:
                    logging.info("Sending LOGOUT command to server...")
                    self.client.send("LOGOUT")
                    # Add a short timeout to receive the response
                    try:
                        response = self.client.recv(SIZE)
                        logging.info(f"Logout response: {response}")
                    except socket.timeout:
                        logging.warning("Timeout waiting for logout response")
                    
                    # Close the socket
                    self.client.sock.close()
                    logging.info("Socket closed successfully")
                except Exception as e:
                    logging.error(f"Error during disconnect: {e}")
                finally:
                    self.client = None
                    self.connection_alive = False
                    logging.info("Connection marked as disconnected")
    
    def update_activity(self):
        self.last_activity = time.time()
    
    def check_idle_timeout(self):
        if not self.connection_alive:
            return False
            
        current_time = time.time()
        if current_time - self.last_activity > self.activity_timeout:
            logging.info(f"Connection idle for {self.activity_timeout} seconds, disconnecting...")
            self.disconnect()
            return True
        return False
    
    def __del__(self):
        self.disconnect()

class ConnectionRegistry:
    """Registry of all active connections"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ConnectionRegistry, cls).__new__(cls)
                cls._instance._init()
            return cls._instance
    
    def _init(self):
        self.connections = {}
        self.cleanup_thread = threading.Thread(target=self._cleanup_monitor, daemon=True)
        self.cleanup_thread.start()
    
    def create_connection(self):
        """Create a new connection and return its ID"""
        connection_id = str(uuid.uuid4())
        self.connections[connection_id] = UserConnection()
        return connection_id
    
    def get_connection(self, connection_id):
        """Get a connection by ID"""
        if connection_id in self.connections:
            return self.connections[connection_id]
        return None
    
    def remove_connection(self, connection_id):
        """Remove and disconnect a connection"""
        if connection_id in self.connections:
            conn = self.connections[connection_id]
            conn.disconnect()
            del self.connections[connection_id]
    
    def _cleanup_monitor(self):
        """Background thread to clean up idle connections"""
        while True:
            # Make a copy of the keys to avoid modification during iteration
            connection_ids = list(self.connections.keys())
            for connection_id in connection_ids:
                if connection_id in self.connections:
                    conn = self.connections[connection_id]
                    if conn.check_idle_timeout():
                        with self._lock:
                            if connection_id in self.connections:
                                del self.connections[connection_id]
            time.sleep(30)  # Check every 30 seconds

# Singleton registry instance
connection_registry = ConnectionRegistry()