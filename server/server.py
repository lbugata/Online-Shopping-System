import hashlib
import socket
import sys
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_public_key(pubkey_path):
    """Load a public key from a given file path."""
    with open(pubkey_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())

def load_private_key(privkey_path):
    """Load a private key from a given file path."""
    with open(privkey_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

def verify_signature(data, signature, public_key):
    """Verify the signature with the corresponding public key."""
    try:
        if isinstance(data, str):
            data = data.encode()

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def rsa_encrypt(message, pubkey):
    """Encrypt a message using the provided public key."""
    return pubkey.encrypt(message.encode(), padding.PKCS1v15())

def rsa_decrypt(cipher_text, privkey):
    """Decrypt a cipher text using the provided private key."""
    return privkey.decrypt(cipher_text, padding.PKCS1v15())

def receive_data(sock):
    """Receive data from a socket."""
    return sock.recv(1024)

def send_data(sock, data):
    """Send data through a socket."""
    sock.sendall(data)

def manage_connection(client_sock, client_addr, financial_host, financial_port):
    """Handle incoming client requests and manage client connection."""
    try:
        print(f'Client connected from {client_addr}')
        while True:
            request_data = receive_data(client_sock)
            if not request_data:
                break
            handle_request(client_sock, client_addr, request_data, financial_host, financial_port)
    except Exception as e:
        print(f"Error with client at {client_addr}: {e}")
    finally:
        client_sock.close()
        print(f"Connection with {client_addr} closed.")

def handle_request(client_sock, client_addr, request_data, financial_host, financial_port):
    """Determine the type of request and route it appropriately."""
    request_text = request_data.decode()
    if request_text == "FETCH ITEMS":
        dispatch_item_list(client_sock, client_addr)
    else:
        relay_to_financial(client_sock, client_addr, request_data, financial_host, financial_port)

def dispatch_item_list(client_sock, client_addr):
    """Send item list from file to client."""
    try:
        items = read_items("item.txt")
        send_data(client_sock, items.encode())
        print(f"Sent item list to {client_addr}")
    except Exception as e:
        print(f"Failed to dispatch items to {client_addr}: {e}")

def read_items(file_path):
    """Read items from a file."""
    with open(file_path, "r") as item_file:
        return item_file.read()

def relay_to_financial(client_sock, client_addr, data, financial_host, financial_port):
    """Forward client data to the financial server and send back the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as financial_sock:
            financial_sock.connect((financial_host, financial_port))
            send_data(financial_sock, data)
            response = receive_data(financial_sock)
        send_data(client_sock, response)
        print(f"Processed and relayed financial response to {client_addr}")
    except Exception as e:
        print(f"Communication failure with financial server for {client_addr}: {e}")

def launch_server(financial_host, financial_port, local_port):
    """Initialize the server and manage incoming connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(('', local_port))
        server_sock.listen()
        print(f"Server listening on {local_port}")
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                threading.Thread(target=manage_connection, args=(client_sock, client_addr, financial_host, financial_port)).start()
            except KeyboardInterrupt:
                print("Server shutdown initiated.")
                break

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage error: Correct format: python3 serv.py <financial_host> <financial_port> <local_port>")
    else:
        financial_host = sys.argv[1]
        financial_port = int(sys.argv[2])
        local_port = int(sys.argv[3])
        launch_server(financial_host, financial_port, local_port)
