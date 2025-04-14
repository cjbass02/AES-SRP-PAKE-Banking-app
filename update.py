import os
import sys
import re
import importlib.util
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

VERSION_FILE = "current_version.txt"
PUBLIC_KEY_FILE = "update_public_key.pem"

def get_current_version(default="1.0.0"):
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, "r") as f:
            return f.read().strip()
    return default

def set_current_version(version):
    with open(VERSION_FILE, "w") as f:
        f.write(version)

def version_tuple(version_str):
    return tuple(map(int, version_str.split('.')))

def verify_update_signature(update_path):
    """
    Verifies the update file signature.
    The signature file must be in the same folder with the same basename but a .sig extension.
    """
    sig_path = os.path.splitext(update_path)[0] + ".sig"
    if not os.path.exists(sig_path):
        print("Signature file missing for update:", update_path)
        return False
    try:
        with open(update_path, "rb") as f:
            update_data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()
        if not os.path.exists(PUBLIC_KEY_FILE):
            print("Public key file missing:", PUBLIC_KEY_FILE)
            return False
        with open(PUBLIC_KEY_FILE, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        public_key.verify(
            signature,
            update_data,
            ec.ECDSA(hashes.SHA256())
        )
        print(f"Verified update file signature for {os.path.basename(update_path)}.")
        return True
    except Exception as e:
        print("Signature verification failed:", e)
        return False

def check_for_updates(current_version, role, rollout_dir="rollouts"):
    if not os.path.isdir(rollout_dir):
        return current_version, None

    pattern = re.compile(f"{role}_v(\\d+\\.\\d+\\.\\d+)_update\\.py")
    updates = []
    for filename in os.listdir(rollout_dir):
        m = pattern.fullmatch(filename)
        if m:
            ver = m.group(1)
            if version_tuple(ver) > version_tuple(current_version):
                updates.append((filename, ver))
    if not updates:
        return current_version, None
    updates.sort(key=lambda x: version_tuple(x[1]))
    latest_file, latest_ver = updates[-1]
    update_path = os.path.join(rollout_dir, latest_file)
    # Verify the update file's signature before returning it.
    if verify_update_signature(update_path):
        return latest_ver, update_path
    else:
        print("Update signature verification failed. Update will not be applied.")
        return current_version, None

def apply_update(update_path, new_version):
    module_name = "update_patch"
    spec = importlib.util.spec_from_file_location(module_name, update_path)
    update_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(update_module)
    if hasattr(update_module, "apply_patch"):
        update_module.apply_patch()
        set_current_version(new_version)
        print("Update applied successfully. Restarting server...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    else:
        print("Error: update module does not contain apply_patch().")










# import os
# import sys
# import importlib.util
# import re
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import ec

# VERSION_FILE = "current_version.txt"

# def get_current_version(default="1.0.0"):
#     if os.path.exists(VERSION_FILE):
#         with open(VERSION_FILE, "r") as f:
#             return f.read().strip()
#     return default

# def set_current_version(version):
#     with open(VERSION_FILE, "w") as f:
#         f.write(version)

# def version_tuple(version_str):
#     return tuple(map(int, version_str.split('.')))

# def check_for_updates(current_version, role, rollout_dir="rollouts", public_key_path="update_public_key.pem"):
#     if not os.path.exists(rollout_dir):
#         return current_version, None

#     pattern = re.compile(f"{role}_v(\\d+\\.\\d+\\.\\d+)_update\\.py")
#     available_updates = []
#     for filename in os.listdir(rollout_dir):
#         if filename.endswith(".py") and filename.startswith(f"{role}_v"):
#             match = pattern.search(filename)
#             if match:
#                 ver = match.group(1)
#                 if version_tuple(ver) > version_tuple(current_version):
#                     available_updates.append((filename, ver))
#     if not available_updates:
#         return current_version, None

#     available_updates.sort(key=lambda x: version_tuple(x[1]))
#     latest_file, latest_version = available_updates[-1]
#     update_path = os.path.join(rollout_dir, latest_file)
#     signature_filename = os.path.splitext(latest_file)[0] + ".sig"
#     signature_path = os.path.join(rollout_dir, signature_filename)
#     if not os.path.exists(signature_path):
#         print("Update file signature missing!")
#         return current_version, None

#     with open(update_path, "rb") as uf:
#         update_data = uf.read()
#     with open(signature_path, "rb") as sf:
#         signature = sf.read()

#     if not os.path.exists(public_key_path):
#         print("Public key for update verification missing!")
#         return current_version, None

#     with open(public_key_path, "rb") as key_file:
#         public_key = serialization.load_pem_public_key(key_file.read())

#     try:
#         public_key.verify(
#             signature,
#             update_data,
#             ec.ECDSA(hashes.SHA256())
#         )
#         print(f"Verified update file '{latest_file}' with version {latest_version}.")
#     except Exception as e:
#         print("Update verification failed:", e)
#         return current_version, None

#     return latest_version, update_path

# def apply_update(update_path, new_version):
#     module_name = "update_patch"
#     spec = importlib.util.spec_from_file_location(module_name, update_path)
#     if spec is None:
#         print("Could not load update module spec.")
#         return False

#     update_module = importlib.util.module_from_spec(spec)
#     try:
#         spec.loader.exec_module(update_module)
#     except Exception as e:
#         print("Error executing update module:", e)
#         return False

#     if hasattr(update_module, "apply_patch") and callable(update_module.apply_patch):
#         try:
#             update_module.apply_patch()
#             print("Update applied successfully.")
#             # Persist the new version to avoid reapplying this update.
#             set_current_version(new_version)
#             print("Restarting the server automatically...")
#             os.execv(sys.executable, [sys.executable] + sys.argv)
#             return True  # This line will not be reached if execv is successful.
#         except Exception as e:
#             print("Error applying patch:", e)
#             return False
#     else:
#         print("Update module does not contain an 'apply_patch' function.")
#         return False

# if __name__ == "__main__":
#     role = sys.argv[1] if len(sys.argv) > 1 else "server"
#     current_version = get_current_version()
#     new_version, update_path = check_for_updates(current_version, role)
#     if update_path:
#         print(f"New update available for {role}: version {new_version}")
#         apply_update(update_path, new_version)
#     else:
#         print("No new updates available.")
