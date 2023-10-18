import socket
import threading
from common_signals import ready_signalb, ready_signala

host = "10.0.2.15"
send_port = 10200
receive_port = 10201

# Function to handle sending messages
def send_messages(client_socket, ready_signala):
    ready_signala.wait()
    client_socket.connect((host, send_port))
    while True:  
        message = input("Enter a message to send: ")
        client_socket.send(message.encode())
        if message=="Stop":
            break

# Function to handle receiving messages
def receive_messages(receive_server_socket,ready_signalb):
    ready_signalb.set()
    receive_client_socket, addr = receive_server_socket.accept()
    # print("Connection from", addr)
    while True:
        message = receive_client_socket.recv(1024).decode()
        if message=="Stop":
            break
        print("Received message:", message)

def main():
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    receive_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receive_server_socket.bind((host, receive_port))
    receive_server_socket.listen()
    
    # Create two threads to handle sending and receiving messages
    send_thread = threading.Thread(target=send_messages, args=(send_socket,ready_signala))
    receive_thread = threading.Thread(target=receive_messages, args=(receive_server_socket,ready_signalb))

    send_thread.start()
    receive_thread.start()

if __name__ == "__main__":
    main()
