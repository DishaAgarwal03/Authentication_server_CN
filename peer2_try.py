
import socket
import time
from client_copy import login

def main():
    auth_keys=["100","200","300","400","500"]
    f=0
    # authentication first - login - auth key generation
    auth_key=login()

    while True:
        if f==0:
            choice=int(input("1. Listen for connections \n2. Initiate a connection \n3. Exit \nEnter choice: "))

        if(choice==1 or f==1):  # server
            # Configuration
            f=0
            HOST = '10.0.2.15'
            PORT = 12350

            # Create a socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((HOST, PORT))
            server_socket.listen()

            print("Server is listening on {}:{}".format(HOST, PORT))
            
            client_socket, addr = server_socket.accept()
            print("Connection from", addr)
            
            # Verification of the connection received
            
            # receiving client's auth key
            client_auth_key = client_socket.recv(1024).decode()
            if client_auth_key not in auth_keys:
                client_socket.sendall(b"You are not an authenticated user")
                client_socket.close()
                print("The user who tried to connect is not authenticated")
                continue
            client_socket.sendall(b"You are verified")
            while True:
                
                client_msg = client_socket.recv(1024).decode()
                print("Friend: " ,client_msg)
                if client_msg.lower()=="stop":
                    break
                
                server_msg = input("You: ").encode()
                client_socket.sendall(server_msg)
                if server_msg.decode().lower()=="stop":
                    break
                
            client_socket.close()
            server_socket.close()
                
        elif (choice==2):   # client
            # Configuration
            HOST = '10.0.2.15'
            PORT = 12349
            
            # Create a socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            while True:
                try:
                    client_socket.connect((HOST, PORT))
                    print("Sending my authentication key")
                    break
                except ConnectionRefusedError as e:
                        print(f"Connection to {HOST}:{PORT} refused. \n1. Retry \n2. Start Listening \n3. Exit")
                        ch=int(input("Enter choice: "))
                        
                        if ch==1:            
                            time.sleep(5)
                            continue
                        elif ch==2:
                            f=1
                            break
                        else:
                            exit(0)
            if f==1:
                continue
            my_auth_key = auth_key.encode()
            client_socket.sendall(my_auth_key)
            
            server_msg = client_socket.recv(1024).decode()
            
            if server_msg=="You are not an authenticated user":
                print("Not authenticated")
                client_socket.close()
                continue
            else:
                print("You can chat now")
                while True:
                    
                    client_msg = input("You: ").encode()
                    client_socket.sendall(client_msg)
                    if client_msg.decode().lower()=="stop":
                        break
                    
                    server_msg = client_socket.recv(1024).decode()
                    print("Friend: " ,server_msg)
                    if server_msg.lower()=="stop":
                        break

            client_socket.close()
            
        elif choice==3:
            print("Exiting...")
            exit(0)

        else:
            print("Wrong Choice")
            continue

if __name__ == "__main__":
    main()
    