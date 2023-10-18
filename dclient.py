# HAS ISSUES
# DON'T USE THIS

import socket

HOST = "10.0.2.15"  # The server's hostname or IP address
PORT = 10200  # The port used by the server
flag=1

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        # Enter your username
        flag=1
        data = s.recv(256)
        data = str(data, 'UTF-8')
        print(f"Server: {data}")
        username = input().encode()
        s.sendall(username)
        
        cmd = str(s.recv(256), 'UTF-8')
        while(flag==1):
            # Enter your password means correct username was typed
            if(cmd=="Enter your password"):
                print(f"Server: {cmd}")
                pwd = input().encode()
                s.sendall(pwd)
                msg = str(s.recv(256), 'UTF-8')
                
                # Sucessful login
                if(msg=="You are connected"):
                    s.close()
                    
                # Wrong password
                else:
                    print(f"Server: {msg}")
                    cmd = str(s.recv(256), 'UTF-8')
                    
                    # Enter choice: password again?
                    print(f"Server: {cmd}")
                    choice = input().encode()
                    s.sendall(choice)
                    
                    ch = str(choice, 'UTF-8')
                    if(ch=="N" or ch=="n"):
                        s.close()
                    elif(ch=="Y" or ch=="y"):
                        continue
                    else:
                        msg = str(s.recv(256), 'UTF-8')
                        print(f"Server: {msg}")
                        continue
                    
            # Wrong username was typed
            elif(cmd=="A) Register \nB) Re-enter username \nC) Exit \nEnter choice: "):
                print(f"Server: {cmd}")
                choice=input().encode()
                s.sendall(choice)
                ch = str(choice, 'UTF-8')
                # Exit
                if(ch=="C" or ch=="c"):
                    s.close()
                # Re-enter username
                elif(ch=="B" or ch=="b"):
                    break
                # Register
                elif(ch=="A" or ch=="a"):
                    while(True):
                        # Enter new username
                        cmd = str(s.recv(256), 'UTF-8')
                        print(f"Server: {cmd}")
                        reg_username=input().encode()
                        s.sendall(reg_username)
                        
                        cmd = str(s.recv(256), 'UTF-8')
                        # If username already exists then enter new username again
                        if(cmd=="Username already exists."):
                            continue
                        # If unique username entered then make new password
                        cmd = str(s.recv(256), 'UTF-8')
                        print(f"Server: {cmd}")
                        reg_pwd=input().encode()
                        s.sendall(reg_pwd)
                        
                        # Successfully registered
                        msg = str(s.recv(256), 'UTF-8')
                        print(f"Server: {msg}")
                        
                        # Login or exit
                        cmd = str(s.recv(256), 'UTF-8')
                        print(f"Server: {cmd}")
                        choice=input().encode()
                        s.sendall(choice)
                        ch = str(choice, 'UTF-8')
                        # Exit
                        if(ch=="N" or ch=="n"):
                            s.close()
                        # If Login after Registering
                        elif(choice=="Y" or choice=="y"):
                            flag=0
                            break
                        else:
                            msg = str(s.recv(256), 'UTF-8')
                            print(f"Server: {msg}")
                            s.close()      
                # Wrong choice -> re-enter username
                else:
                    msg = str(s.recv(256), 'UTF-8')
                    print(f"Server: {msg}")
                    break
                