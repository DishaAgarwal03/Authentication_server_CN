# Peer B establishing connection
import socket
import threading

def send_message():
    while True:
        message = input("Peer B: ")
        peer_a_socket.send(message.encode('utf-8'))

def receive_message():
    while True:
        data = peer_a_socket.recv(1024)
        print(f"Peer A: {data.decode('utf-8')}")

peer_a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peer_a_socket.connect(("127.0.0.1", 8888))

send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)

send_thread.start()
receive_thread.start()
