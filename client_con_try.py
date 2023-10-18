import socket

# Define the server's address and port
SERVER_HOST = '10.0.2.15'
SERVER_PORT = 12345

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((SERVER_HOST, SERVER_PORT))

while True:
    message = input("Enter a message to send to the server (or 'quit' to exit): ")
    
    if message.lower() == 'quit':
        break

    # Send the message to the server
    client_socket.send(message.encode('utf-8'))
    
    # Receive and display the server's response
    response = client_socket.recv(1024)
    print("Server Response: " + response.decode('utf-8'))

# Close the client socket
client_socket.close()
