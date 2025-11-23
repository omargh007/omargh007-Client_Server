#done by Razan

import hashlib
from io import TextIOBase
import logging
import os
import socket
import sys
import threading
from threading import Lock
import time

IP = "127.0.0.1"  
PORT = 4456
ADDR = (IP, PORT)
SIZE = 1024
SERVER_DATA_PATH = "server_data"
file_lock = Lock()
MESSAGE_DELIMITER = b"\r\n"  # Delimiter to separate commands


#https://stackoverflow.com/questions/17277566/check-os-path-isfilefilename-with-case-sensitive-in-python
def isfile_casesensitive(path):
    """Check if the file exists in the directory with case-sensitive matching."""
    if not os.path.isfile(path):
        return False   # exit early
    directory, filename = os.path.split(path)
    return filename in os.listdir(directory)  # This checks if the file exists with the correct case

#got this from https://realpython.com/python-logging/ and https://docs.python.org/3/library/logging.html
logging.basicConfig(
    level=logging.INFO,  
    format="%(asctime)s - %(levelname)s - %(message)s",  
    handlers=[
        logging.FileHandler("server.log"), 
        logging.StreamHandler()
    ]
)


class MyTimeoutError(Exception):
    pass

#got this from https://ashutoshvarma.github.io/blog/timeout-on-function-call-in-python
def timeout_func(func, args=None, kwargs=None, timeout=30, default=None):
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = default
            self.exc_info = (None, None, None)
        
        def run(self):
            try:
                self.result = func(*(args or ()), **(kwargs or {}))
            except Exception as err:
                self.exc_info = sys.exc_info()

    it = InterruptableThread()
    it.start()
    it.join(timeout)

    if it.exc_info[0] is not None:
        raise it.exc_info[1]

    if it.is_alive():
        raise MyTimeoutError(f"{func.__name__} timeout (exceeded {timeout} sec)")
    
    return it.result

class TimeoutSocket:
    def __init__(self, sock, timeout_seconds=30):
        self.sock = sock
        self.timeout_seconds = timeout_seconds
        self.buffer = b""  # Buffer to store incomplete messages
    
    def send(self, data):
        # Add delimiter to end of message
        if isinstance(data, str):
            data = data.encode("utf-8")
        return timeout_func(self.sock.sendall, args=(data + MESSAGE_DELIMITER,), timeout=self.timeout_seconds)
    
    def recv(self, size, no_timeout=False):
        if no_timeout:
            data = self.sock.recv(size)
            self.buffer += data
            return self._process_buffer()
        return timeout_func(self._recv_with_buffer, args=(size,), timeout=self.timeout_seconds, default=b"")
    
    def _recv_with_buffer(self, size):
        # If we already have a complete message in buffer, return it
        if MESSAGE_DELIMITER in self.buffer:
            message, self.buffer = self.buffer.split(MESSAGE_DELIMITER, 1)
            return message
            
        # Otherwise receive more data
        data = self.sock.recv(size)
        if not data:
            return b""
            
        self.buffer += data
        
        # Check if we now have a complete message
        if MESSAGE_DELIMITER in self.buffer:
            message, self.buffer = self.buffer.split(MESSAGE_DELIMITER, 1)
            return message
            
        # Return what we have if it's been a while
        if len(self.buffer) > 0:
            return self.buffer
        
        # If still no complete message, return empty
        return b""
    
    def _process_buffer(self):
        # Check if we have a complete message in the buffer
        if MESSAGE_DELIMITER in self.buffer:
            message, self.buffer = self.buffer.split(MESSAGE_DELIMITER, 1)
            return message
        # If no complete message, return empty for now and keep in buffer
        return b""

    def recv_exact(self, size):
        """Receive exactly 'size' bytes, with no message framing."""
        received = 0
        data = b""
        while received < size:
            chunk = self.sock.recv(min(size - received, SIZE))
            if not chunk:
                break
            data += chunk
            received += len(chunk)
        return data

# got this from http://medium.com/@tubelwj/how-to-read-extremely-large-text-files-in-python-cddc7dbce9fc
block_size=1024*8  # 8 KB
def chunked_file_reader(fp, block_size):
    while True:
        chunk = fp.read(block_size)
        if not chunk:
            break
        yield chunk
#till here

#got this from https://medium.com/@sebastienwebdev/file-integrity-monitor-in-python-a-beginners-guide-fedefc9d9284
def calculate_file_hash(filepath):
    """Calculate the SHA512 hash of a file."""
    hash_sha512 = hashlib.sha512()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha512.update(chunk)
    return hash_sha512.hexdigest()
#till here

#omar updated this for timstamp and size in lisitng page
def list_files(conn):
    if not os.path.exists(SERVER_DATA_PATH):
        os.makedirs(SERVER_DATA_PATH)
    files = os.listdir(SERVER_DATA_PATH)
    send_data = "OK@"

    if not files:
        send_data += "The server directory is empty."
    else:
        file_details = []
        for filename in files:
            filepath = os.path.join(SERVER_DATA_PATH, filename)
            if os.path.isfile(filepath):
                # Get file size in bytes
                file_size = os.path.getsize(filepath)
                # Get last modification time
                mod_time = os.path.getmtime(filepath)
                # Format the time as a readable string
                time_str = time.ctime(mod_time)
                # Append the details
                detail_str = f"{filename}|{file_size}|{time_str}"
                file_details.append(detail_str)
                # Add debug logging
                logging.info(f"Adding file detail: {detail_str}")
        
        send_data += "\n".join(file_details)
        # Add debug logging for the final message
        logging.info(f"Sending file listing: {send_data}")
    conn.send(send_data)

def download_file(conn, data, addr):
    if len(data) < 2:
        conn.send("ERROR@Invalid command format.")
        return

    filename = data[1]
    start_byte = 0
    
    # Check if start_byte is provided (for resuming download)
    if len(data) > 2:
        try:
            start_byte = int(data[2])
        except (ValueError, IndexError):
            start_byte = 0

    filepath = os.path.join(SERVER_DATA_PATH, filename)

    if not os.path.exists(filepath):
        conn.send("ERROR@File not found.")
        return
        
    file_size = os.path.getsize(filepath)
    hash_value = calculate_file_hash(filepath)
    
    # Send the remaining size of the file
    remaining_size = file_size - start_byte
    conn.send(f"OK@{remaining_size}")
    conn.send(hash_value)
    
    try:
        ack = conn.recv(SIZE)
        if not ack or ack.decode() != "ACK":
            logging.error(f"[ERROR] No ACK received from {addr}")
            return

        logging.info(f"Starting file download to client: {filename} from byte {start_byte}")
        
        with file_lock:
            with open(filepath, 'rb') as fp:
                # Skip to the start byte for resuming
                if start_byte > 0:
                    fp.seek(start_byte)
                    
                # Send the file content
                for chunk in chunked_file_reader(fp, block_size):
                    conn.sock.sendall(chunk)  # Use direct socket send to avoid delimiter

        # Send end marker separately to avoid confusion with file data
        conn.sock.sendall(b"@#$END")
        
        logging.info(f"Finished file download to client: {filename}")
    except Exception as e:
        logging.error(f"[ERROR] During download: {e}")
        conn.send(f"ERROR@{str(e)}")
def upload_file(conn, data):
    try:
        filename = data[1]
        original_filename = filename
        
        # Parse the filename to handle versioning
        name_parts = os.path.splitext(filename)
        base_name = name_parts[0]
        extension = name_parts[1] if len(name_parts) > 1 else ""
        
        # Check if file exists and increment version if needed
        filepath = os.path.join(SERVER_DATA_PATH, filename)
        version = 0
        
        # Count existing versions of this file
        existing_versions = 0
        for file in os.listdir(SERVER_DATA_PATH):
            # Count files that match base name pattern (either exact or with _vX)
            if file == filename or file.startswith(f"{base_name}_v") and file.endswith(extension):
                existing_versions += 1
        
        logging.info(f"Found {existing_versions} existing version(s) of {base_name}{extension}")
        
        while os.path.exists(filepath):
            version += 1
            filename = f"{base_name}_v{version}{extension}"
            filepath = os.path.join(SERVER_DATA_PATH, filename)
        
        # Notify client if we had to rename the file
        if version > 0:
            logging.info(f"File '{original_filename}' already exists. Saving as '{filename}' (Version {version} of {existing_versions + 1})")
        
        expected_hash = conn.recv(SIZE).decode("utf-8")
        conn.send("READY")
        
        response = conn.recv(SIZE).decode("utf-8")
        if not response.startswith("OK@"):
            logging.error(f"Error: {response}")
            return
            
        file_size = int(response.split("@")[1])
        
        logging.info(f"Starting file upload: {filename} ({file_size} bytes)")
        conn.send("ACK")

        # For file data, use direct socket receive without message framing
        received_size = 0
        with file_lock:
            with open(filepath, "wb") as f:
                while received_size < file_size:
                    chunk = conn.sock.recv(min(SIZE, file_size - received_size))
                    if not chunk:
                        logging.error("[ERROR] Connection lost during file transfer.")
                        conn.send("ERROR@Connection lost")
                        return
                    f.write(chunk)
                    received_size += len(chunk)
                    
        # Look for end marker
        end_marker = b""
        while len(end_marker) < 6:
            chunk = conn.sock.recv(1)
            if not chunk:
                break
            end_marker += chunk
            if end_marker[-6:] == b"@#$END":
                break
        
        delivered_hash = calculate_file_hash(filepath)
        if expected_hash == delivered_hash:
            # Include the potentially renamed filename and version info in the success message
            if version > 0:
                version_info = f"Version {version} of {existing_versions + 1} total versions"
                logging.info(f"File '{original_filename}' uploaded as '{filename}' successfully. {version_info}")
                conn.send(f"SUCCESS@{filename}@{version}@{existing_versions + 1}")
            else:
                logging.info(f"File '{filename}' uploaded successfully. First version of this file.")
                conn.send(f"SUCCESS@{filename}@0@1")
        else:
            logging.error(f"File hash mismatch. Expected: {expected_hash}, Got: {delivered_hash}")
            conn.send("ERROR@File integrity check failed")
            
    except IndexError:
        logging.error("[ERROR] Incorrect command format: UPLOAD <filename>")
    except Exception as e:
        logging.error(f"[ERROR] An unexpected error occurred: {e}")
          
def delete_file(conn, data):
    if len(data) < 2:
        conn.send("ERROR@Invalid command format.")
        return
    filename = data[1]
    filepath = os.path.join(SERVER_DATA_PATH, filename)
    #got this from https://www.w3schools.com/python/python_file_remove.asp
    if isfile_casesensitive(filepath):  # changed to use isfile_casesensitive
        os.remove(filepath)
        conn.send("OK@File deleted successfully.")
    else:
        conn.send("ERROR@File not found.")

def help_command(conn):
    help_msg = """
                            OK@Available Commands:
                            - LIST: List all files on the server.
                            - UPLOAD <filename>: Upload a file.
                            - DOWNLOAD <filename>: Download a file.
                            - DELETE <filename>: Delete a file.
                            - LOGOUT: Disconnect from the server.
                            - HELP: Show this help message.
                            """
    conn.send(help_msg)

def else_command(conn):
     conn.send("ERROR@Invalid command.")

def handle_conn(connn, addr):
    logging.info(f"[NEW CONNECTION] {addr} connected.")
    conn = TimeoutSocket(connn, timeout_seconds=10)  # Increased from 5 to 10 seconds
    conn.send("OK@Welcome to the File Server.")
    
    while True:
        try:
            raw_data = conn.recv(SIZE, no_timeout=True)
            if not raw_data:
                logging.info(f"[DISCONNECTED] {addr} disconnected (no data)")
                break
                
            data_str = raw_data.decode("utf-8")
            data = data_str.split("@")
            cmd = data[0]

            logging.info(f"[COMMAND] {addr}: {cmd}")
            
            if cmd == "LIST":
                list_files(conn)
            elif cmd == "DOWNLOAD":
                download_file(conn, data, addr)
            elif cmd == "UPLOAD":
                upload_file(conn, data)
            elif cmd == "DELETE":
                delete_file(conn, data)
            elif cmd == "LOGOUT":
                logging.info(f"[LOGOUT] {addr} requested logout")
                conn.send("OK@Goodbye!")
                break
            elif cmd == "HELP":
                help_command(conn)
            else:
                else_command(conn)

        except (ConnectionResetError, BrokenPipeError):
            logging.error(f"[DISCONNECTED] {addr} disconnected unexpectedly.")
            break
        except Exception as e:
            logging.error(f"[ERROR] {addr}: {e}")
            try:
                conn.send(f"ERROR@Server error: {e}")  
            except:
                pass
            break

    logging.info(f"[DISCONNECTED] {addr} disconnected")
    connn.close()

def main():
    logging.info("[STARTING] Server is starting...")
    
    # Create server data directory if it doesn't exist
    if not os.path.exists(SERVER_DATA_PATH):
        os.makedirs(SERVER_DATA_PATH)
        
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(ADDR)
        server.listen()
        logging.info(f"[LISTENING] Server is listening on {IP}:{PORT}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_conn, args=(conn, addr))
            thread.daemon = True  # Make thread daemon so it exits when main thread exits
            thread.start()
            logging.info(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

    except KeyboardInterrupt:
        shutdown_server(server)
    except Exception as e:
        logging.error(f"[ERROR] {e}")
        shutdown_server(server)

def shutdown_server(server):
    logging.info("\n[SHUTDOWN] Server is shutting down...")
    server.close()
    logging.info("[SERVER STOPPED]")

if __name__ == "__main__":
    main()