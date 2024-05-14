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

def read_credit_info(file_path):
    """Load credit details from a specified file."""
    account_details = {}
    try:
        with open(file_path, "r") as file:
            for record in file:
                account_details.update(parse_credit_record(record))
    except Exception as e:
        print(f"Failed to read or parse credit info file: {e}")
        sys.exit(1)
    return account_details

def parse_credit_record(record):
    """Parse a single credit record into components."""
    record_stripped = record.strip()
    customer_name, card_hash, available_credit = record_stripped.split()
    return {customer_name: (card_hash, int(available_credit))}

def check_credit_sufficiency(credits, deduct_amount):
    """Check if the available credits are sufficient for the deduction."""
    return credits >= deduct_amount

def update_credit_info(file_path, accounts_info):
    """Write updated credit details back to file."""
    try:
        with open(file_path, "w") as file:
            for customer, (card_hash, credits) in accounts_info.items():
                file.write(f"{customer} {card_hash} {credits}\n")
    except Exception as e:
        print(f"Error writing to credit info file: {e}")
        raise

def modify_credit_details(customer, deduct_amount, accounts_info):
    """Modify credit details based on the transaction."""
    try:
        card_hash, credits = accounts_info[customer]
        if check_credit_sufficiency(credits, deduct_amount):
            credits -= deduct_amount
            accounts_info[customer] = (card_hash, credits)
            update_credit_info("creditinfo.txt", accounts_info)
            return True
    except KeyError:
        print(f"No matching customer record found: {customer}")
    except Exception as e:
        print(f"Error occurred while updating credit info: {e}")
    return False

def handle_client_connection(connection, account_info):
    """Handle individual client connections."""
    print('New client connected:', connection.getpeername())
    try:
        while True:
            client_data = receive_data(connection)
            if client_data:
                process_client_request(client_data, account_info, connection)
            else:
                break
    except Exception as e:
        print(f"Exception during client connection: {e}")

def receive_data(sock):
    """Receive data from the socket."""
    return sock.recv(1024).decode()

def process_client_request(client_data, account_info, connection):
    """Process incoming client data and respond accordingly."""
    try:
        client_name, card_hash, transaction_amount = client_data.split()
        amount = int(transaction_amount)
        if process_transaction(client_name, card_hash, amount, account_info, connection):
            connection.sendall(b"Transaction Approved")
        else:
            connection.sendall(b"Transaction Denied")
    except ValueError:
        connection.sendall(b"Received malformed amount")
    except Exception as e:
        print(f"Exception processing transaction request: {e}")

def process_transaction(client_name, card_hash, amount, account_info, connection):
    """Process a transaction request and validate it against stored credit information."""
    if client_name in account_info and modify_credit_details(client_name, amount, account_info):
        return card_hash == account_info[client_name][0]
    return False

def run_server(host, port_number):
    """Start the server and manage connections."""
    account_info = read_credit_info("creditinfo.txt")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port_number))
        sock.listen()
        print(f"Bank server active on {host}:{port_number}")
        try:
            while True:
                connection, address = sock.accept()
                handle_client_connection(connection, account_info)
        except KeyboardInterrupt:
            print("Server shutdon initiated by user")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Incorrect usage. Correct format: python bank.py <host> <port_number>")
    else:
        host = sys.argv[1]
        port_number = int(sys.argv[2])
        run_server(host, port_number)
