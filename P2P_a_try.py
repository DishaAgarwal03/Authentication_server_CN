# Peer A waiting for connection
import socket
import threading

def send_message():
    while True:
        message = input("Peer A: ")
        peer_b_socket.send(message.encode('utf-8'))

def receive_message():
    while True:
        data = peer_b_socket.recv(1024)
        print(f"Peer B: {data.decode('utf-8')}")

peer_a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peer_a_socket.bind(("0.0.0.0", 8888))
peer_a_socket.listen(5)

print("[*] Peer A is waiting for a connection...")
peer_b_socket, _ = peer_a_socket.accept()
print("[*] Peer B connected!")

send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)

send_thread.start()
receive_thread.start()
