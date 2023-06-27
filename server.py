import socket

import utils

from cryptography.hazmat.primitives import serialization, hashes


def sign_up(client_socket, public_key,  private_key):
    username = client_socket.recv(1024).decode()
    password = client_socket.recv(1024).decode()

    client_public_key = client_socket.recv(1024).decode()

    # decrypt password
    decrypted_password = utils.decrypt_message_with_private_key(
        password, private_key)

    # get hashed data
    hashed_data = client_socket.recv(1024).decode()
    verify = utils.verify_signature_with_public_key(
        hashed_data, utils.hash_string(username + client_public_key + password), client_public_key)
    # compare hashed data with decrypted password
    if verify:
        return username

    return None


def handle_client(client_socket, public_key,  private_key):
    while True:
        command = client_socket.recv(1024).decode()

        if command == 'exit':
            break
        elif command == 'su':
            sign_up(client_socket, public_key,  private_key)

    client_socket.close()


def start_server():
    host = '127.0.0.1'
    port = 12345

    utils.generate_key_pair()
    private_key = utils.load_private_key()
    public_key = utils.load_public_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print('Server listening on {}:{}'.format(host, port))

    while True:
        client_socket, addr = server_socket.accept()
        print('Connection from:', addr)

        # Send the public key to the client
        client_socket.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        handle_client(client_socket, public_key=public_key,
                      private_key=private_key)


if __name__ == '__main__':
    start_server()
