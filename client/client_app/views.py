#Done by Omar 

# views.py
import os
import hashlib
import logging
import json
from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse
from django.conf import settings
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden

# Import the connection registry
from .connection_manager import connection_registry

# Your constants
CLIENT_DATA_PATH = os.path.join(settings.BASE_DIR, "client_data")
metadata_dir = os.path.join(settings.BASE_DIR, "metadata")
SIZE = 1024

# Create folders if not exists
os.makedirs(CLIENT_DATA_PATH, exist_ok=True)
os.makedirs(metadata_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)

def calculate_file_hash(filepath):
    hash_sha512 = hashlib.sha512()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha512.update(chunk)
    return hash_sha512.hexdigest()

def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('Home')
    else:
        form = UserCreationForm()
    return render(request, "client_app/register.html", {"form": form})

# ----------------- SESSION CONNECTION MANAGEMENT -----------------

def get_user_connection(request):
    """Get the user's connection from the registry using session ID"""
    if 'connection_id' not in request.session:
        # Create a new connection and store its ID in the session
        connection_id = connection_registry.create_connection()
        request.session['connection_id'] = connection_id
    
    # Get the connection from the registry
    connection = connection_registry.get_connection(request.session['connection_id'])
    
    # If connection was expired/removed, create a new one
    if connection is None:
        connection_id = connection_registry.create_connection()
        request.session['connection_id'] = connection_id
        connection = connection_registry.get_connection(connection_id)
    
    return connection

def close_user_connection(request):
    """Close and remove the user's connection"""
    if 'connection_id' in request.session:
        connection_id = request.session['connection_id']
        try:
            connection = connection_registry.get_connection(connection_id)
            if connection:
                logging.info(f"Closing connection {connection_id}")
                # This will send the LOGOUT command
                connection.disconnect()
            
            # Now remove from registry
            logging.info(f"Removing connection {connection_id} from registry")
            connection_registry.remove_connection(connection_id)
            
            # Clear from session
            del request.session['connection_id']
            logging.info("Connection ID removed from session")
        except Exception as e:
            logging.error(f"Error during connection close: {e}")

# ----------------- VIEWS -----------------

def home(request):
    # Assuming you have a list of files in CLIENT_DATA_PATH directory
    files = os.listdir(CLIENT_DATA_PATH)
    return render(request, "client_app/Home.html", {"files": files})

@login_required
def list_files(request):
    try:
        # Get connection from registry using session
        connection = get_user_connection(request)
        client = connection.get_connection()
        
        if not client:
            return HttpResponse("Error: Could not connect to server")
        
        # Send LIST command to server
        client.send("LIST")
        raw_response = client.recv(SIZE * 10)  # Increase buffer size to handle more files
        
        # Log the raw response bytes for debugging
        logging.info(f"Raw response bytes: {raw_response}")
        
        try:
            response = raw_response.decode("utf-8")
            logging.info(f"Decoded response: '{response}'")
        except UnicodeDecodeError:
            logging.error(f"Failed to decode response")
            return HttpResponse("Error: Could not decode server response")
        
        # Initialize files list
        files_with_details = []
        
        if response.startswith("OK@"):
            content = response[3:]  # Skip the "OK@" prefix
            logging.info(f"Content after OK@: '{content}'")
            
            if content == "The server directory is empty.":
                logging.info("Server directory is empty")
            else:
                # Split content by newlines to get each file's details
                file_lines = content.strip().split('\n')
                logging.info(f"Found {len(file_lines)} file entries")
                
                for line in file_lines:
                    logging.info(f"Processing line: '{line}'")
                    
                    if '|' in line:
                        # Split by the pipe delimiter
                        parts = line.split('|')
                        logging.info(f"Split into parts: {parts}")
                        
                        if len(parts) >= 3:
                            filename = parts[0].strip()
                            size_str = parts[1].strip()
                            modified_str = '|'.join(parts[2:]).strip()  # Join remaining parts in case the timestamp contains |
                            
                            try:
                                size = int(size_str)
                                formatted_size = format_file_size(size)
                            except ValueError:
                                logging.warning(f"Could not parse size '{size_str}'")
                                formatted_size = f"Unknown: {size_str}"
                            
                            files_with_details.append({
                                'name': filename,
                                'size': formatted_size,
                                'modified': modified_str
                            })
                        else:
                            # Not enough parts
                            logging.warning(f"Not enough parts in '{line}'")
                            files_with_details.append({
                                'name': parts[0].strip(),
                                'size': 'Parsing Error',
                                'modified': 'Parsing Error'
                            })
                    else:
                        # No delimiter found
                        logging.warning(f"No delimiter in '{line}'")
                        files_with_details.append({
                            'name': line.strip(),
                            'size': 'Unknown',
                            'modified': 'Unknown'
                        })
        else:
            # Not a valid OK response
            logging.warning(f"Invalid response format: '{response}'")
            return HttpResponse(f"Error: Invalid server response format")
        
        # Log what we're passing to the template
        logging.info(f"Files with details: {files_with_details}")
        
        return render(request, "client_app/list_files.html", {"files": files_with_details})
        
    except Exception as e:
        logging.error(f"Error during list files: {e}", exc_info=True)
        close_user_connection(request)
        return HttpResponse(f"Error: {e}")
    
def format_file_size(size_bytes):
    """Format file size from bytes to KB, MB, GB"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.2f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"

from django.http import JsonResponse
import json

@login_required
def upload_file(request):
    if request.method == "POST":
        uploaded_file = request.FILES["file"]
        filepath = os.path.join(CLIENT_DATA_PATH, uploaded_file.name)
        try:
            # Saving file locally
            with open(filepath, "wb") as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            logging.info(f"File {uploaded_file.name} saved locally.")
            
            # Get connection from registry using session
            connection = get_user_connection(request)
            client = connection.get_connection()
            
            if not client:
                return JsonResponse({"status": "error", "message": "Could not connect to server"})
                
            client.send(f"UPLOAD@{uploaded_file.name}")
            hashing = calculate_file_hash(filepath)
            client.send(hashing)

            response = client.recv(SIZE).decode("utf-8")
            if response != "READY":
                logging.error(f"Upload failed for {uploaded_file.name}: Server not ready.")
                return JsonResponse({"status": "error", "message": f"Server error: {response}"})
            
            file_size = os.path.getsize(filepath)
            client.send(f"OK@{file_size}")

            ack = client.recv(SIZE).decode("utf-8")
            if ack != "ACK":
                logging.error(f"Upload failed for {uploaded_file.name}: No ACK received.")
                return JsonResponse({"status": "error", "message": "No ACK received."})

            # Send the file content with progress tracking
            sent_bytes = 0
            with open(filepath, 'rb') as fp:
                for chunk in iter(lambda: fp.read(8192), b""):
                    client.sock.sendall(chunk)
                    sent_bytes += len(chunk)
                    # No need to update progress here as we'll use JavaScript for that

            client.sock.sendall(b"@#$END")
            final_response = client.recv(SIZE).decode("utf-8")
            logging.info(f"Upload finished for {uploaded_file.name}: {final_response}")
            return JsonResponse({"status": "success", "message": f"Upload finished: {final_response}"})

        except Exception as e:
            logging.error(f"Error during upload: {e}")
            # On error, ensure connection is reset for next attempt
            close_user_connection(request)
            return JsonResponse({"status": "error", "message": f"Error during upload: {e}"})

    return render(request, "client_app/upload.html")

@login_required
def download_file(request, filename):
    try:
        # Get connection from registry using session
        connection = get_user_connection(request)
        client = connection.get_connection()
        
        if not client:
            return HttpResponse("Error: Could not connect to server")
            
        client.send(f"DOWNLOAD@{filename}@0")
        response = client.recv(SIZE).decode("utf-8")

        if not response.startswith("OK@"):
            logging.error(f"Download failed for {filename}: {response}")
            return HttpResponse(f"Error: {response}")

        size = int(response.split("@")[1])
        expected_hash = client.recv(SIZE).decode("utf-8")

        client.send("ACK")

        filepath = os.path.join(CLIENT_DATA_PATH, filename)
        with open(filepath, "wb") as f:
            received = 0
            while received < size:
                chunk = client.sock.recv(min(SIZE, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                # No direct progress update here as we're in a synchronous view

        end_marker = client.sock.recv(6)
        if end_marker != b"@#$END":
            logging.error(f"Download failed for {filename}: Invalid file end marker.")
            return HttpResponse("Invalid file end marker.")

        actual_hash = calculate_file_hash(filepath)
        if actual_hash != expected_hash:
            logging.error(f"Download failed for {filename}: Hash mismatch (file may be corrupted).")
            return HttpResponse("Hash mismatch! File may be corrupted.")

        logging.info(f"File {filename} downloaded successfully.")
        return FileResponse(open(filepath, 'rb'), as_attachment=True, filename=filename)

    except Exception as e:
        logging.error(f"Error during download: {e}")
        # On error, ensure connection is reset for next attempt
        close_user_connection(request)
        return HttpResponse(f"Error during download: {e}")

# Add a new view for file upload progress
@login_required
def upload_progress(request):
    """Return the upload progress and speed for AJAX calls"""
    if request.method == "POST" and request.is_ajax():
        if 'file_size' in request.session and 'uploaded' in request.session:
            file_size = request.session['file_size']
            uploaded = request.session['uploaded']
            percent = int(uploaded * 100 / file_size) if file_size > 0 else 0
            return JsonResponse({
                'uploaded': uploaded,
                'file_size': file_size,
                'percent': percent
            })
    return JsonResponse({'percent': 0})

def save_metadata(filename, metadata_dict):
    metadata_file = os.path.join(metadata_dir, f"{filename}_metadata.json")
    with open(metadata_file, 'w') as f:
        json.dump(metadata_dict, f)
    logging.info(f"Metadata for {filename} saved. Status: {metadata_dict['status']}, Position: {metadata_dict['last_received_byte']}/{metadata_dict['total_size']}")

def load_metadata(filename):
    metadata_file = os.path.join(metadata_dir, f"{filename}_metadata.json")
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            try:
                metadata = json.load(f)
                logging.info(f"Loaded metadata for {filename}: {metadata}")
                return metadata
            except json.JSONDecodeError:
                logging.error(f"Failed to parse metadata for {filename}")
                return None
    return None

@login_required
def download_file(request, filename):
    try:
        # Get connection from registry using session
        connection = get_user_connection(request)
        client = connection.get_connection()
        
        if not client:
            return HttpResponse("Error: Could not connect to server")
        
        # Parse the filename
        name_parts = os.path.splitext(filename)
        base_name = name_parts[0]
        extension = name_parts[1] if len(name_parts) > 1 else ""

        # STEP 1: Scan for existing versions
        existing_versions = {}
        for file in os.listdir(CLIENT_DATA_PATH):
            if file == filename:
                existing_versions[0] = file
            elif file.startswith(f"{base_name}_v") and file.endswith(extension):
                try:
                    version_str = file[len(base_name) + 2 : -len(extension)] if extension else file[len(base_name) + 2 :]
                    version = int(version_str)
                    existing_versions[version] = file
                except ValueError:
                    continue

        # STEP 2: Check for incomplete downloads
        resume_filename = None
        resume_metadata = None
        for version, file in existing_versions.items():
            metadata = load_metadata(file)
            if metadata and metadata.get('status') == 'incomplete':
                resume_filename = file
                resume_metadata = metadata
                break

        if resume_filename:
            # Resume incomplete download
            local_filename = resume_filename
            filename_to_download = resume_metadata.get('original_filename', filename)
            start_byte = resume_metadata.get('last_received_byte', 0)
            logging.info(f"Resuming incomplete download: {local_filename} from byte {start_byte}")
        else:
            # No incomplete file, create new version
            if 0 not in existing_versions:
                local_filename = filename
            else:
                next_version = max(existing_versions.keys()) + 1
                local_filename = f"{base_name}_v{next_version}{extension}"
            filename_to_download = filename
            start_byte = 0
            logging.info(f"Starting fresh download: {local_filename}")

        # STEP 3: Start download
        client.send(f"DOWNLOAD@{filename_to_download}@{start_byte}")
        response = client.recv(SIZE).decode("utf-8")

        if response.startswith("OK@"):
            try:
                remaining_size = int(response.split("@")[1])
                expected_hash = client.recv(SIZE).decode("utf-8")

                filepath = os.path.join(CLIENT_DATA_PATH, local_filename)

                client.send("ACK")

                mode = "ab" if start_byte > 0 else "wb"
                with open(filepath, mode) as f:
                    received_size = 0
                    total_size = start_byte + remaining_size

                    save_metadata(local_filename, {
                        'filename': local_filename,
                        'original_filename': filename_to_download,
                        'last_received_byte': start_byte,
                        'total_size': total_size,
                        'status': 'incomplete'
                    })

                    while received_size < remaining_size:
                        data = client.sock.recv(min(SIZE, remaining_size - received_size))
                        if not data:
                            break
                        f.write(data)
                        received_size += len(data)
                        current_position = start_byte + received_size

                        if received_size % (1024 * 1024) == 0:
                            save_metadata(local_filename, {
                                'filename': local_filename,
                                'original_filename': filename_to_download,
                                'last_received_byte': current_position,
                                'total_size': total_size,
                                'status': 'incomplete'
                            })

                # Receive end marker
                end_marker = b""
                while len(end_marker) < 6:
                    chunk = client.sock.recv(1)
                    if not chunk:
                        break
                    end_marker += chunk
                    if end_marker[-6:] == b"@#$END":
                        break

                # STEP 4: Verify hash
                if received_size == remaining_size:
                    actual_hash = calculate_file_hash(filepath)
                    if actual_hash != expected_hash:
                        logging.error("[ERROR] File was not received correctly (hash mismatch).")
                        save_metadata(local_filename, {
                            'filename': local_filename,
                            'original_filename': filename_to_download,
                            'last_received_byte': start_byte + received_size,
                            'total_size': total_size,
                            'status': 'corrupted'
                        })
                        return HttpResponse("Hash mismatch! File may be corrupted.")
                    else:
                        logging.info(f"File '{local_filename}' downloaded successfully.")
                        save_metadata(local_filename, {
                            'filename': local_filename,
                            'original_filename': filename_to_download,
                            'last_received_byte': total_size,
                            'total_size': total_size,
                            'status': 'complete'
                        })
                        return FileResponse(open(filepath, 'rb'), as_attachment=True, filename=local_filename)
                else:
                    current_position = start_byte + received_size
                    save_metadata(local_filename, {
                        'filename': local_filename,
                        'original_filename': filename_to_download,
                        'last_received_byte': current_position,
                        'total_size': total_size,
                        'status': 'incomplete'
                    })
                    logging.error(f"Warning: Incomplete download. Expected {remaining_size} bytes, got {received_size} bytes. You can resume later.")
                    return HttpResponse(f"Incomplete download. You can resume later.")

            except ValueError:
                logging.error(f"[ERROR] Invalid file size response: {response}")
                return HttpResponse(f"Invalid file size response: {response}")
        else:
            logging.error(f"Error: {response.split('@')[1]}")
            return HttpResponse(f"Error: {response.split('@')[1]}")

    except Exception as e:
        logging.error(f"Error during download: {e}")
        # On error, ensure connection is reset for next attempt
        close_user_connection(request)
        return HttpResponse(f"Error during download: {e}")

@login_required
def delete_file(request, filename):
    if not hasattr(request.user, 'profile') or request.user.profile.role != 'admin':
        return HttpResponseForbidden("You do not have permission to delete files.")
    try:
        # Get connection from registry using session
        connection = get_user_connection(request)
        client = connection.get_connection()
        
        if not client:
            return HttpResponse("Error: Could not connect to server")
            
        client.send(f"DELETE@{filename}")
        response = client.recv(SIZE).decode("utf-8")
        
        # Log the response for debugging
        logging.info(f"Delete response: {response}")
        
        # Check if the file deletion was successful
        if "success" in response.lower():
            logging.info(f"File {filename} deleted successfully.")
            return redirect('Home')
        else:
            return HttpResponse(f"Error during file deletion: {response}")

    except Exception as e:
        logging.error(f"Error during deletion: {e}")
        # On error, ensure connection is reset for next attempt
        close_user_connection(request)
        return HttpResponse(f"Error: {e}")

@login_required
def help_view(request):
    try:
        connection = get_user_connection(request)
        client = connection.get_connection()

        if not client:
            return HttpResponse("Error: Could not connect to server")

        client.send("HELP")
        response = client.recv(SIZE).decode("utf-8")

        # Use render to load the help.html and pass help_text
        return render(request, "client_app/help.html", {"help_text": response})
        
    except Exception as e:
        logging.error(f"Error: {e}")
        close_user_connection(request)
        return HttpResponse(f"Error: {e}")

# Add a logout handler to properly disconnect

from django.contrib.auth import logout as auth_logout

@login_required
def logout_connection(request):
    # First close the socket connection
    logging.info("Starting logout process")
    close_user_connection(request)
    
    # Then perform Django logout
    logging.info("Performing Django authentication logout")
    auth_logout(request)
    
    # Redirect to home or login page
    return redirect('Home')  # or 'login'

#meta data
import os

# Metadata folder for storing download status
METADATA_FOLDER = os.path.join(os.getcwd(), 'metadata')

# Create the metadata folder if it doesn't exist
if not os.path.exists(METADATA_FOLDER):
    os.makedirs(METADATA_FOLDER)

# Function to get the last downloaded byte for a specific file
def get_download_metadata(filename):
    metadata_path = os.path.join(METADATA_FOLDER, filename + ".txt")
    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            return int(f.read())  # Return the last byte received
    return 0  # If no metadata exists, start from the beginning

# Function to update the metadata after downloading a chunk
def update_download_metadata(filename, last_byte_received):
    metadata_path = os.path.join(METADATA_FOLDER, filename + ".txt")
    with open(metadata_path, "w") as f:
        f.write(str(last_byte_received))  # Save the last byte received
