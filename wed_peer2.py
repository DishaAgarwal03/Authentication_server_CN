
import socket
import time
from wed_peer_functions import login, verify_initiator, update_logout, key_generation
from wed_peer_functions import retrieve_listener_details_auth_key, retrieve_listener_details_username

def main():
    MAIN_SERVER_HOST = '10.0.2.15'  # The server's MAIN_SERVER_HOSTname or IP address
    MAIN_SERVER_PORT = 10200 # The port used by the server
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((MAIN_SERVER_HOST, MAIN_SERVER_PORT))
    # auth_keys=["100","200","300","400","500"]
    f=0
    # authentication first - login - auth key generation
    key=key_generation(s)
    auth_key=login(s=s, key=key)

    while True:
        if f==0:
            choice=int(input("1. Listen for connections \n2. Initiate a connection \n3. Exit \nEnter choice: "))

        if(choice==1 or f==1):  # server
            # Configuration
            f=0
            HOST, PORT = retrieve_listener_details_auth_key(s=s, key=key, auth_key=auth_key)

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
            if not verify_initiator(s=s, key=key, client_auth_key=client_auth_key):
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
            username=input("Enter username of user you want to talk to: ")
            HOST, PORT = retrieve_listener_details_username(s=s, key=key, username=username)
            
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
            s.close()
            update_logout(s=s, key=key, auth_key=auth_key)
            print("Exiting...")
            exit(0)

        else:
            print("Wrong Choice")
            continue

if __name__ == "__main__":
    main()
    