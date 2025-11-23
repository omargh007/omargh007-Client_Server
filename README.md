This project is a File Sharing System built with Django for the client side and an independent server script (server.py) for handling server operations.

🚀 How to Run the Project
1. Clone or Download the Project
First, clone or download the project files to your machine.

2. Install Python and Required Packages
Make sure Python 3 is installed.

Install Django:
pip install django
(Optionally, you can create and activate a virtual environment.)

3. Running the Server (Backend)
Open a terminal and navigate to the project root

Run the server script:

python server.py runserver
This will start the independent server responsible for handling backend operations.

4. Running the Client (Django App)
Open another terminal.

Navigate to the client directory:

cd client
Run the Django development server:

python manage.py runserver
The Django client application will start, usually accessible at:
http://127.0.0.1:8000/

🛠 Project Structure

client_server-main/
│
├── server.py        # Independent server code
│
└── client/
    ├── manage.py    # Django project manager
    ├── client_app/  # (Your Django app folder)
    └── ...          # Other Django settings, migrations, etc.
⚡ Features
Upload, download, and manage files.

Django-based frontend client.

Independent backend server handling file operations separately.

📋 Notes
Always make sure both the server and client are running when using the system.(server first)

If ports are busy or conflicts occur, you may need to specify a custom port when running the servers.
