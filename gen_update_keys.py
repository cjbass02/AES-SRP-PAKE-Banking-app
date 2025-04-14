from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate a private key using the SECP256R1 curve.
private_key = ec.generate_private_key(ec.SECP256R1())

# Save the private key (without a password for simplicity)
with open("update_private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Extract and save the public key.
public_key = private_key.public_key()
with open("update_public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("Key pair generated: update_private_key.pem and update_public_key.pem")
