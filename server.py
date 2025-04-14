import datetime
import socket
import os
import sys
import shutil
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from update import get_current_version, check_for_updates, apply_update, set_current_version

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

# Initially, create a dummy cipher; this will be replaced after SRP auth.
dummy_key = Fernet.generate_key()
cipher = Fernet(dummy_key)

def encrypt_message(message):
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message):
    return cipher.decrypt(encrypted_message).decode()

# --- Enhanced Account Class with SRP ---
class Account:
    def __init__(self, number, password, balance=0):
        self.number = number
        self.balance = balance
        # SRP setup: generate a random salt and compute the verifier (v = g^x mod N)
        self.salt = secrets.randbits(64) 
        x = H_int(format(self.salt, 'x'), password)
        self.verifier = pow(g, x, N)
    
    def deposit(self, amount):
        self.balance += amount
        return f"Deposit of ${amount} successful. New balance: ${self.balance}"
    
    def withdraw(self, amount):
        if amount > self.balance:
            return "Insufficient funds"
        self.balance -= amount
        return f"Withdraw of ${amount} successful. New balance: ${self.balance}"
    
    def check_balance(self):
        return f"Current balance: ${self.balance}"
    
    def get_number(self):
        return self.number
    
    def loan(self, amount):
        if amount <= 2 * self.balance:
            self.balance += amount
            return f"Loan of {amount} approved. New balance: {self.balance}"
        else:
            return "Loan amount too high"

def srp_server_auth(conn, account):
    print("\n--- [Server SRP] Starting Authentication ---")
    # Step 1: Wait for SRP initialization from the client
    data = conn.recv(1024).decode()
    print(f"[Server Debug] Received: {data}")
    if not data.startswith("SRP_INIT:"):
        conn.sendall("Error: Expected SRP_INIT".encode())
        conn.close()
        sys.exit(1)
    # Extract account number from the message
    username = data.split(":", 1)[1].strip()
    print(f"[Server Debug] Account number received: {username}")
    if username != str(account.get_number()):
        conn.sendall("Error: Unknown account".encode())
        conn.close()
        sys.exit(1)
    
    # Step 2: Generate server ephemeral value (b), compute B and send the SRP challenge
    # Compute B = (k*v + g^b mod N) mod N, where v is the verifier.
    b = secrets.randbits(256)  # Server's random private ephemeral value
    B = (k * account.verifier + pow(g, b, N)) % N
    print(f"[Server Debug] Private ephemeral b (random): {b}")
    print(f"[Server Debug] Computed server ephemeral B: {B} (hex: {format(B, 'x')})")
    
    # Construct the challenge message which includes:
    # - The salt 
    # - The servers B
    challenge_msg = "SRP_CHALLENGE:" + format(account.salt, 'x') + "," + format(B, 'x')
    print(f"[Server Debug] Sending SRP challenge (salt and B): {challenge_msg}")
    conn.sendall(challenge_msg.encode())
    
    # Step 3: Receive client's ephemeral value A (plaintext)
    data = conn.recv(1024).decode()
    print(f"[Server Debug] Received: {data}")
    if not data.startswith("SRP_A:"):
        conn.sendall("Error: Expected SRP_A".encode())
        conn.close()
        sys.exit(1)
    A = int(data.split(":", 1)[1], 16)
    print(f"[Server Debug] Received client ephemeral A: {A} (hex: {format(A, 'x')})")
    
    # Step 4: Compute scrambling parameter (u) and the shared session key on the server side
    u = H_int(format(A, 'x'), format(B, 'x'))
    S_server = pow((A * pow(account.verifier, u, N)) % N, b, N)
    K_server = H_hash(str(S_server))
    print(f"[Server Debug] Computed scrambling parameter u: {u}")
    print(f"[Server Debug] Computed shared secret S_server: {S_server}")
    print(f"[Server Debug] Derived session key K_server (SHA-256 of S_server): {K_server.hex()}")
    
    # Step 5: Verify client's proof (M1)
    data = conn.recv(1024).decode()
    print(f"[Server Debug] Received client proof message: {data}")
    if not data.startswith("SRP_M1:"):
        conn.sendall("Error: Expected SRP_M1".encode())
        conn.close()
        sys.exit(1)
    M1_client = int(data.split(":", 1)[1], 16)
    expected_M1 = H_int(format(A, 'x'), format(B, 'x'), K_server.hex())
    print(f"[Server Debug] Expected client proof M1: {expected_M1} (hex: {format(expected_M1, 'x')})")
    if M1_client != expected_M1:
        conn.sendall("Error: Client proof mismatch".encode())
        conn.close()
        sys.exit(1)
    
    # Step 6: Send server proof (M2) back to client
    M2 = H_int(format(A, 'x'), format(M1_client, 'x'), K_server.hex())
    m2_msg = "SRP_M2:" + format(M2, 'x')
    print(f"[Server Debug] Computed server proof M2: {M2} (hex: {format(M2, 'x')})")
    print(f"[Server Debug] Sending server proof message: {m2_msg}")
    conn.sendall(m2_msg.encode())
    print("[Server Debug] SRP authentication successful!")
    
    # Step 7: Re-key the encryption cipher with the SRP-derived session key
    fernet_key = base64.urlsafe_b64encode(K_server)
    global cipher
    cipher = Fernet(fernet_key)
    print(f"[Server Debug] Re-keying successful. New encryption key (from session key): {K_server.hex()}")
    print("--- [Server SRP] Authentication Complete ---")

def handle_command(command, account):
    parts = command.split()
    if parts[0] == "withdraw" and len(parts) > 1 and parts[1].isdigit():
        return account.withdraw(int(parts[1]))
    elif parts[0] == "deposit" and len(parts) > 1 and parts[1].isdigit():
        return account.deposit(int(parts[1]))
    elif parts[0] == "balance":
        return f"Balance: {account.balance}"
    elif parts[0] == "loan" and len(parts) > 1 and parts[1].isdigit():
        return account.loan(int(parts[1]))
    elif parts[0] == "update":
        check_updates()
    else:
        return "Invalid command"

def run_server(host="127.0.0.1", port=5000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server: Listening on {host}:{port}")
    
    conn, addr = server_socket.accept()
    print(f"Server: Connected by {addr}")
    
    # For this demo, create an account (account number “123” with password “secret123”)
    account = Account("admin", "password")
    
    # Perform SRP authentication before handling any commands
    srp_server_auth(conn, account)
    
    # Command loop: send prompt, process command, and respond using the re-keyed cipher.
    while True:
        if CURRENT_VERSION == "1.0.0":
            conn.sendall(encrypt_message("Enter Command (withdraw <amount>, deposit <amount>, balance, update, exit): "))
        else:
            conn.sendall(encrypt_message("Enter Command (withdraw <amount>, deposit <amount>, balance, loan, update, exit): "))
        command = decrypt_message(conn.recv(1024))
        print(f"Server received command: {command}")
        if command.lower() == "exit":
            conn.sendall(encrypt_message("Goodbye"))
            break
        bank_response = handle_command(command, account)
        conn.sendall(encrypt_message(bank_response))
        if "success" in bank_response or "Balance" in bank_response:
            log_action(bank_response, account)
    conn.close()
    print("Server: Connection closed")

def log_action(action, account):
    date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    with open("msg_log.txt", "a") as f:
        f.write(f"{date_time}\n - Account {account.get_number()} - {action}\n")

def check_updates():
    new_version, update_path = check_for_updates(CURRENT_VERSION, ROLE)
    if update_path:
        print(f"New update found for {ROLE}! Updating SERVER to version {new_version} from {update_path}.")
        legacy_folder = "legacy"
        if not os.path.exists(legacy_folder):
            os.makedirs(legacy_folder)
        shutil.copy(__file__, os.path.join(legacy_folder, f"{os.path.splitext(os.path.basename(__file__))[0]}_v{CURRENT_VERSION}.py"))
        set_current_version(new_version)
        apply_update(update_path, new_version)
    else:
        print("No new updates available for server. Running current version.")
        run_server()

if __name__ == "__main__":
    ROLE = "server"
    CURRENT_VERSION = get_current_version()
    print(f"Current {ROLE} version: {CURRENT_VERSION}")
    run_server()


# import datetime
# import socket
# import os
# import sys
# from cryptography.fernet import Fernet
# from update import get_current_version, check_for_updates, apply_update, set_current_version
# import shutil

# # Define your classes and functions first.
# class Account:
#     def __init__(self, number, balance=0):
#         self.number = number
#         self.balance = balance

#     def deposit(self, amount):
#         self.balance += amount
#         return f"Deposit of ${amount} successful. New balance: ${self.balance}"
    
#     def withdraw(self, amount):
#         if amount > self.balance:
#             return "Insufficient funds"
#         self.balance -= amount
#         return f"Withdraw of ${amount} successful. New balance: ${self.balance}"
    
#     def check_balance(self):
#         return f"Current balance: ${self.balance}"
    
#     def get_number(self):
#         return self.number
    
#     def loan(self, amount):
#         # Approve loan if the amount is <= twice the current balance.
#         if amount <= 2 * self.balance:
#             self.balance += amount
#             return f"Loan of {amount} approved. New balance: {self.balance}"
#         else:
#             return "Loan amount too high"

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


# def check_updates():
#     # Perform update check AFTER all globals (like Account, handle_command) are defined.
#     new_version, update_path = check_for_updates(CURRENT_VERSION, ROLE)
#     if update_path:
#         print(f"New update found for {ROLE}! Updating SERVER to version {new_version} from {update_path}.")
#         legacy_folder = "legacy"
#         if not os.path.exists(legacy_folder):
#             os.makedirs(legacy_folder)
#         shutil.copy(__file__, os.path.join(legacy_folder, f"{os.path.splitext(os.path.basename(__file__))[0]}_v{CURRENT_VERSION}.py"))
#         set_current_version(new_version)
#         apply_update(update_path, new_version)
#     else:
#         print("No new updates available for server. Running current version.")
#         run_server()

# def handle_command(command, account):
#     parts = command.split()
#     if parts[0] == "withdraw" and len(parts) > 1 and parts[1].isdigit():
#         return account.withdraw(int(parts[1]))
#     elif parts[0] == "deposit" and len(parts) > 1 and parts[1].isdigit():
#         return account.deposit(int(parts[1]))
#     elif parts[0] == "balance":
#         return f"Balance: {account.balance}"
#     elif parts[0] == "loan" and len(parts) > 1 and parts[1].isdigit():
#         return account.loan(int(parts[1]))
#     elif parts[0] == "update":
#         check_updates()
#     else:
#         return "Invalid command"

# def run_server(host="127.0.0.1", port=5000):
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     server_socket.bind((host, port))
#     server_socket.listen(1)
#     print(f"Server: Listening on {host}:{port}")

#     conn, addr = server_socket.accept()
#     print(f"Server: Connected by {addr}")

#     account = Account(123)

#     # Account verification: receive account number from client
#     while True:
#         data = conn.recv(1024)
#         if not data:
#             break
#         decoded = decrypt_message(data)
#         if decoded.startswith("account:"):
#             acct_num = decoded.split(":", 1)[1].strip()
#             if acct_num == str(account.get_number()):
#                 conn.sendall(encrypt_message("Account verified"))
#                 break
#             else:
#                 conn.sendall(encrypt_message("Incorrect account number"))
    
#     # Command loop: send prompt to client, receive command, process it, and send back the response
#     while True:
#         if(CURRENT_VERSION == "1.0.0"):
#             conn.sendall(encrypt_message("Enter Command (withdraw <amount>, deposit <amount>, balance, update, exit): "))
#         else:
#             conn.sendall(encrypt_message("Enter Command (withdraw <amount>, deposit <amount>, balance, loan, update, exit): "))
#         command = decrypt_message(conn.recv(1024))
#         print(f"Server received command: {command}")
#         if command.lower() == "exit":
#             conn.sendall(encrypt_message("Goodbye"))
#             break
#         bank_response = handle_command(command, account)
#         conn.sendall(encrypt_message(bank_response))
#         if "success" in bank_response or "Balance" in bank_response:
#             log_action(bank_response, account)
#     conn.close()
#     print("Server: Connection closed")

# def log_action(action, account):
#     date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
#     with open("msg_log.txt", "a") as f:
#         f.write(f"{date_time}\n - Account {account.get_number()} - {action}\n")

# # --- Main Entry Point ---
# if __name__ == "__main__":
#     ROLE = "server"
#     # Instead of a hardcoded version, read it from a file.
#     CURRENT_VERSION = get_current_version()  
#     print(f"Current {ROLE} version: {CURRENT_VERSION}")
#     run_server()
#     # # Perform update check AFTER all globals (like Account, handle_command) are defined.
#     # new_version, update_path = check_for_updates(CURRENT_VERSION, ROLE)
#     # if update_path:
#     #     print(f"New update found for {ROLE}! Updating SERVER to version {new_version} from {update_path}.")
#     #     apply_update(update_path, new_version)
#     # else:
#     #     print("No new updates available for server. Running current version.")
#     #     
