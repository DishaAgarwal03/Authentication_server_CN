import socket
import threading

# Define the server's address and port
HOST = '10.0.2.15'
PORT = 12345

# Function to handle a single client connection
def handle_client(client_socket):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        # Process the data as needed
        print("Received: " + data.decode('utf-8'))
        response = "Server received your message: " + data.decode('utf-8')
        client_socket.send(response.encode('utf-8'))
    client_socket.close()

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((HOST, PORT))

# Start listening for incoming connections
server_socket.listen(5)
print(f"Server listening on {HOST}:{PORT}")

while True:
    # Accept a client connection
    client_socket, client_address = server_socket.accept()
    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")
    
    # Create a new thread to handle the client
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()
