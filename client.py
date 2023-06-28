import socket
import utils


def signup(socket):
    username = input('Enter username: ')
    socket.send(username.encode())

    client_public_key = utils.load_public_key()
    socket.send(client_public_key.encode())

    password = input('Enter password: ')
    password = utils.encrypt_message_with_public_key(
        password, utils.load_public_key())
    socket.send(password.encode())

    hashed_data = utils.sign_message_with_private_key(
        utils.hash_string(username + client_public_key + password), utils.load_private_key())
    socket.send(hashed_data.encode())


def handle_client_functions(socket):
    while True:
        command = input('Enter command: ')

        if command == 'exit':
            break
        elif command == 'su':
            signup(socket)

    socket.close()


def start_client():

    host = '127.0.0.1'
    port = 12345

    utils.generate_key_pair()
    private_key = utils.load_private_key()
    public_key = utils.load_public_key()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    print('Connected to {}:{}'.format(host, port))

    handle_client_functions(client_socket)


if __name__ == '__main__':
    start_client()
