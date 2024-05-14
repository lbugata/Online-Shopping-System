import hashlib
import socket
import sys
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_public_key(path):
    """Load a public key from a PEM file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read(), backend=default_backend())

def encrypt_message(message, public_key):
    """Encrypt a message using RSA public key encryption."""
    return public_key.encrypt(message.encode(), padding.PKCS1v15())

def load_private_key(path):
    """Load a private key from a PEM file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), None, backend=default_backend())

def sign_data(data, private_key):
    """Sign data using a private key."""
    if isinstance(data, str):
        data = data.encode()
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def decrypt_message(encrypted_message, private_key):
    """Decrypt an encrypted message using RSA private key decryption."""
    return private_key.decrypt(encrypted_message, padding.PKCS1v15())

def create_hash(data):
    """Create a SHA-512 hash of the data."""
    hash_object = hashlib.sha512(data.encode())
    return f"H({hash_object.hexdigest()})"

def receive_message(sock):
    """Receive a message from the socket and print the content."""
    try:
        response = sock.recv(4096).decode()
        if response:
            print("Debug: Received data from server:")
            print(response)  # Print the received data to ensure it's visible in the output.
        else:
            print("Debug: No data received or empty response.")
        return response
    except socket.error as e:
        print(f"Socket error: {e}")
        return ""


def send_message(sock, message):
    """Send a message to the socket."""
    sock.sendall(message.encode())

def parse_items_data(items_data):
    """Parse items data from a string to a dictionary."""
    items = {}
    for line in items_data.splitlines():
        if line:
            item_id, name, price = line.split()
            items[item_id] = {'name': name, 'price': int(price)}
    return items

def get_user_input(prompt, validation_func=None):
    """Get validated user input using a prompt."""
    while True:
        input_value = input(prompt)
        if not validation_func or validation_func(input_value):
            return input_value
        print("Invalid input, please try again.")

def validate_positive_integer(value):
    """Validate that the provided string is a positive integer."""
    try:
        return int(value) > 0
    except ValueError:
        return False

def manage_cart(items):
    """Manage the shopping cart interactions."""
    cart = {}
    while True:
        item_id = get_user_input("Enter item ID: ", lambda x: x in items)
        cart[item_id] = 1
        if get_user_input("Add more items to cart? (y/n): ", lambda x: x.lower() in ('y', 'n')) == 'n':
            break
    return cart

def calculate_cart_total(cart, items):
    """Calculate the total cost of the cart."""
    return sum(items[item_id]['price'] * qty for item_id, qty in cart.items())

def display_cart(cart, items):
    """Display the cart contents."""
    for item_id, qty in cart.items():
        item = items[item_id]
        print(f"{qty} x {item['name']} @ ${item['price']} each")

def initiate_checkout(cart, items):
    """Initiate the checkout process and handle payment."""
    total = calculate_cart_total(cart, items)
    display_cart(cart, items)
    print(f"Total to pay: ${total}")
    return total

def handle_transaction(sock, items):
    """Handle the full transaction process, from shopping to checkout."""
    if items:
        cart = manage_cart(items)
        if cart:
            total = initiate_checkout(cart, items)
            if total > 0:
                if get_user_input("Proceed to checkout? (y/n): ", lambda x: x.lower() in ('y', 'n')) == 'y':
                    name = get_user_input("Enter your name: ")
                    card_number = get_user_input("Enter your card number: ")
                    card_hash = create_hash(f"{name}-{card_number}")
                    transaction_message = f"{name} {card_hash} {total}"
                    send_message(sock, transaction_message)
                    transaction_response = receive_message(sock)
                    print('Transaction status:', transaction_response)
                else:
                    print("Transaction aborted by user.")
        else:
            print("No items added to the cart.")
    else:
        print("No items available to shop.")

def main(server_host, server_port):
    """Main function to connect to the server and initiate shopping."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_host, server_port))
            print(f"Connected to server at {server_host}:{server_port}")
            print("Start Shopping")  # Confirm that shopping can start.

            # Send the 'FETCH ITEMS' command and process the response
            send_message(sock, "FETCH ITEMS")
            items_data = receive_message(sock)
            if items_data:
                print("Successfully retrieved items list from the server.")
                items = parse_items_data(items_data)
                handle_transaction(sock, items)
            else:
                print("Failed to retrieve items from the server or data is empty.")
    except ConnectionRefusedError:
        print("Unable to connect: Please verify the server's IP and port.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Incorrect usage. Correct format: python3 cli.py <server_host> <server_port>")
    else:
        server_host = sys.argv[1]
        server_port = int(sys.argv[2])
        main(server_host, server_port)
