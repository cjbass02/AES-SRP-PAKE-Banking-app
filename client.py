import socket
import os
import sys
import time
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from update import check_for_updates, apply_update

# Global version for the client
CURRENT_VERSION = "1.0.0"
ROLE = "client"

print(f"Current {ROLE} version: {CURRENT_VERSION}")

# Check for a new client update
new_version, update_path = check_for_updates(CURRENT_VERSION, ROLE)
if update_path:
    print(f"New update found for {ROLE}! Updating CLIENT to version {new_version} from {update_path}.")
    apply_update(update_path)
else:
    print("No new updates available for client. Running current version.")

# --- SRP Parameters and Helper Functions ---
N = int("125617018995153554710546479714086468244499594888726646874671447258204721048803")
g = 2
def H_hash(*args):
    h = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            h.update(format(arg, 'x').encode())
        elif isinstance(arg, bytes):
            h.update(arg)
        else:
            h.update(arg.encode())
    return h.digest()

def H_int(*args):
    return int.from_bytes(H_hash(*args), 'big')

# Compute multiplier parameter k = H(N, g)
k = H_int(format(N, 'x'), format(g, 'x'))

# Initially, we keep a dummy cipher; this will be replaced after SRP auth.
dummy_key = Fernet.generate_key()
cipher = Fernet(dummy_key)

def encrypt_message(message):
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message):
    return cipher.decrypt(encrypted_message).decode()

def srp_client_auth(sock):
    print("\n--- [Client SRP] Starting Authentication ---")
    # Step 1: Credential Exchange
    username = input("Enter account number: ")
    password = input("Enter password: ")
    
    # Construct the SRP initialization message
    init_msg = "SRP_INIT:" + username
    print(f"[Client Debug] Sending SRP_INIT message: {init_msg}")
    # Send the SRP_INIT message (plaintext)
    sock.sendall(init_msg.encode())
    
    # Step 2: Receive SRP challenge from server
    # Expected to receive: "SRP_CHALLENGE:<salt>,<B>" where salt and B are hex
    data = sock.recv(1024).decode()
    print(f"[Client Debug] Received challenge from server: {data}")
    if not data.startswith("SRP_CHALLENGE:"):
        print("SRP protocol error: no challenge received.")
        sock.close()
        sys.exit(1)
    
    # Extract the salt and servers (B) from the challenge.
    challenge = data.split(":", 1)[1]
    salt_str, B_str = challenge.split(",")
    salt = int(salt_str, 16)
    B = int(B_str, 16)
    print(f"[Client Debug] Parsed salt: {salt} (hex: {salt_str})")
    print(f"[Client Debug] Parsed server ephemeral value B: {B} (hex: {B_str})")
    
    # Step 3: Compute and send client's ephemeral value A
    a = secrets.randbits(256)  # Client's random private ephemeral value
    A = pow(g, a, N)          # Compute A = g^a mod N
    print(f"[Client Debug] Private ephemeral a (random): {a}")
    print(f"[Client Debug] Computed client ephemeral A: {A} (hex: {format(A, 'x')})")
    # Construct and send the message with A
    A_msg = "SRP_A:" + format(A, 'x')
    print(f"[Client Debug] Sending client ephemeral A message: {A_msg}")
    sock.sendall(A_msg.encode())
    
    # Step 4: Compute shared session key on the client side
    u = H_int(format(A, 'x'), format(B, 'x'))  # Scrambling parameter computed from A and B
    x = H_int(format(salt, 'x'), password)        # Private key derived from salt and password
    gx = pow(g, x, N)                             # Intermediate value: g^x mod N
    S_client = pow((B - k * gx) % N, (a + u * x), N) # Compute client's shared secret S
    K_client = H_hash(str(S_client))              # Session key is hash of S
    print(f"[Client Debug] Computed scrambling parameter u: {u}")
    print(f"[Client Debug] Computed private key x (from salt and password): {x}")
    print(f"[Client Debug] Computed g^x: {gx}")
    print(f"[Client Debug] Computed shared secret S_client: {S_client}")
    print(f"[Client Debug] Derived session key K_client (SHA-256 of S_client): {K_client.hex()}")
    
    # Step 5: Send client proof (M1) to server
    M1_client = H_int(format(A, 'x'), format(B, 'x'), K_client.hex())
    print(f"[Client Debug] Computed client proof M1: {M1_client} (hex: {format(M1_client, 'x')})")
    M1_msg = "SRP_M1:" + format(M1_client, 'x')
    print(f"[Client Debug] Sending client proof message: {M1_msg}")
    sock.sendall(M1_msg.encode())
    
    # Step 6: Receive server proof (M2) and verify
    data = sock.recv(1024).decode()
    print(f"[Client Debug] Received server proof message: {data}")
    if not data.startswith("SRP_M2:"):
        print("SRP protocol error: no server proof received.")
        sock.close()
        sys.exit(1)
    M2_server = int(data.split(":", 1)[1], 16)
    expected_M2 = H_int(format(A, 'x'), format(M1_client, 'x'), K_client.hex())
    print(f"[Client Debug] Expected server proof M2: {expected_M2} (hex: {format(expected_M2, 'x')})")
    if M2_server != expected_M2:
        print("Server authentication failed.")
        sock.close()
        sys.exit(1)
    print("[Client Debug] Server authentication successful!")
    
    # Step 7: Re-key the encryption cipher with the SRP-derived session key
    fernet_key = base64.urlsafe_b64encode(K_client)
    global cipher
    cipher = Fernet(fernet_key)
    print(f"[Client Debug] Re-keying successful. New encryption key (from session key): {K_client.hex()}")
    
def client_run(host="127.0.0.1", port=5000):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Client: Connected to server at {host}:{port}")
    
    # Perform SRP authentication
    srp_client_auth(client_socket)
    
    # Command loop: use the new session key for message encryption
    while True:
        server_prompt = decrypt_message(client_socket.recv(1024))
        print(f"Server prompt: {server_prompt}")
        command = input("Enter command: ")
        client_socket.sendall(encrypt_message(command))
        if command.lower() == "exit":
            print("Exiting.")
            break
        elif command.lower() == "update":
            print("Checking for updates...")
            client_socket.close()
            time.sleep(5)
            client_run(host, port)  # Reconnect after update
            return
        response = decrypt_message(client_socket.recv(1024))
        print(f"Server response: {response}")
    
    client_socket.close()
    print("Client: Connection closed")

if __name__ == "__main__":
    client_run()



# import socket
# import os
# import sys
# from cryptography.fernet import Fernet
# from update import check_for_updates, apply_update
# import time

# # Global version for the client
# CURRENT_VERSION = "1.0.0"
# ROLE = "client"

# print(f"Current {ROLE} version: {CURRENT_VERSION}")

# # Check for a new client update
# new_version, update_path = check_for_updates(CURRENT_VERSION, ROLE)
# if update_path:
#     print(f"New update found for {ROLE}! Updating CLIENT to version {new_version} from {update_path}.")
#     apply_update(update_path)
# else:
#     print("No new updates available for client. Running current version.")

# def generate_key():
#     if not os.path.exists("aes_key.key"):
#         key = Fernet.generate_key()
#         with open("aes_key.key", "wb") as key_file:
#             key_file.write(key)
#     else:
#         with open("aes_key.key", "rb") as key_file:
#             key = key_file.read()
#     return key

# aes_key = generate_key()
# cipher = Fernet(aes_key)

# def encrypt_message(message):
#     return cipher.encrypt(message.encode())

# def decrypt_message(encrypted_message):
#     return cipher.decrypt(encrypted_message).decode()

# def client_run(host="127.0.0.1", port=5000):
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect((host, port))
#     print(f"Client: Connected to server at {host}:{port}")

#     # Account verification: send account number to the server
#     acct_num = input("Enter account number: ")
#     client_socket.sendall(encrypt_message("account:" + acct_num))
#     response = decrypt_message(client_socket.recv(1024))
#     print(f"Server response: {response}")
#     if response != "Account verified":
#         print("Account verification failed. Exiting.")
#         client_socket.close()
#         return

#     # Command loop: receive prompt from server, get user input, and send it
#     while True:
#         server_prompt = decrypt_message(client_socket.recv(1024))
#         print(f"Server prompt: {server_prompt}")
#         command = input("Enter command: ")
#         client_socket.sendall(encrypt_message(command))
#         if command.lower() == "exit":
#             print("Exiting.")
#             break
#         elif command.lower() == "update":
#             print("Checking for updates...")
#             client_socket.close()
#             time.sleep(5) 
#             client_run() # Wait for the server to close the connection
#         response = decrypt_message(client_socket.recv(1024))
#         print(f"Server response: {response}")

#     client_socket.close()
#     print("Client: Connection closed")

# if __name__ == "__main__":
#     client_run()




# # import socket
# # import os
# # from cryptography.fernet import Fernet

# # def generate_key():
# #     """Generate an AES-256 encryption key if it doesn't exist."""
# #     if not os.path.exists("aes_key.key"):
# #         key = Fernet.generate_key()
# #         with open("aes_key.key", "wb") as key_file:
# #             key_file.write(key)
# #     else:
# #         with open("aes_key.key", "rb") as key_file:
# #             key = key_file.read()
# #     return key


# # # Load or generate the encryption key
# # aes_key = generate_key()
# # cipher = Fernet(aes_key)


# # def encrypt_message(message):
# #     """Encrypt the message using AES-256."""
# #     return cipher.encrypt(message.encode())


# # def decrypt_message(encrypted_message):
# #     """Decrypt the message using AES-256."""
# #     return cipher.decrypt(encrypted_message).decode()


# # def run_server(host="127.0.0.1", port=5000):
# #     """A basic TCP server that securely communicates with the client."""
# #     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #     server_socket.bind((host, port))
# #     server_socket.listen(1)
# #     print(f"Receiver: Listening on {host}:{port}")

# #     conn, addr = server_socket.accept()
# #     print(f"Receiver: Connected by {addr}")

# #     try:
# #         while True:
# #             data = conn.recv(1024)
# #             if not data:
# #                 break  # Connection closed by the client
            
# #             decoded = decrypt_message(data)  # Decrypt received message
# #             #print(f"{decoded}")

# #             # Handle prompts based on message type
# #             if "Please enter account number" in decoded:
# #                 user_input = input("Enter an account number: ")
# #                 conn.sendall(encrypt_message(user_input))

# #             elif "Enter Command" in decoded:
# #                 user_input = input("Enter a command (withdraw <amount>, deposit <amount>, balance, exit): ")
# #                 conn.sendall(encrypt_message(user_input))

# #             elif "Incorrect account number" in decoded:
# #                 print(decoded)
# #                 conn.sendall(encrypt_message("ack"))

# #             elif "Invalid command" in decoded:
# #                 print(decoded)
# #                 conn.sendall(encrypt_message("ack"))

# #             elif "success" in decoded or "funds" in decoded or "Balance" in decoded:
# #                 print(decoded)
# #                 conn.sendall(encrypt_message("ack"))

# #     finally:
# #         conn.close()
# #         print("Receiver: Connection closed")


# # if __name__ == "__main__":
# #     run_server()
