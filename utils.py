from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

import os


def generate_key_pair():
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save the private key
    with open('private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b'mypassword')
        ))

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Save the public key
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def load_private_key():
    # Load the private key
    with open('private_key.pem', 'rb') as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(),
            password=b'mypassword'
        )


def load_public_key():
    # Load the public key
    with open('public_key.pem', 'rb') as public_key_file:
        return serialization.load_pem_public_key(
            public_key_file.read()
        )


def generate_key():
    # Generate a new encryption key
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)


def load_key():
    # Load the encryption key
    with open('key.key', 'rb') as key_file:
        return key_file.read()


def encrypt_message_with_public_key(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def decrypt_message_with_private_key(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(

        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()


def sign_message_with_private_key(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature_with_public_key(signature, message, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def encrypt_message_with_symmetric_key(message, symmetric_key):
    cipher_suite = Fernet(symmetric_key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    return encrypted_message


def decrypt_message_with_symmetric_key(encrypted_message, symmetric_key):
    cipher_suite = Fernet(symmetric_key)
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    return decrypted_message.decode()


def hash_string(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()


def generate_nonce():
    return os.urandom(16)


def send_data(data, socket):
    nonce = generate_nonce()
    m = data + nonce
    hashed_data = hash_string(m)
    signature = sign_message_with_private_key(hashed_data, load_private_key())
    socket.sendall(m.encode())
    socket.sendall(signature.encode())


def receive_data(socket):
    data = socket.recv(1024)
    signature = socket.recv(1024)
    hashed_data = hash_string(data)
    if verify_signature_with_public_key(signature, hashed_data, load_public_key()):
        return data
    else:
        return None
