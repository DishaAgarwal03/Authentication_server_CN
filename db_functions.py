# include exception handling
import sqlite3

def create_table(cursor):
  query = """CREATE TABLE IF NOT EXISTS Login
  (
    Username VARCHAR,
    Pwd VARCHAR NOT NULL,
    IP VARCHAR NOT NULL,
    Auth_key NUMERIC,
    PORT NUMERIC,
    
    PRIMARY KEY (Username),
    UNIQUE (IP, PORT),
    UNIQUE (Auth_key),
    CHECK (PORT >= 10200 AND PORT <= 10500)
  );"""
  cursor.execute(query)
  
def insert_table(cursor,username,pwd,ip):
  query = f"INSERT INTO Login (Username, Pwd, IP) VALUES ('{username}', '{pwd}', '{ip}');"
  cursor.execute(query)
  
def display_table(cursor):
  query = "SELECT * FROM Login"
  cursor.execute(query)
  for row in cursor.fetchall():
      for val in row:
          print(val)
      print()
      
def drop_table(cursor):
  query = "DROP TABLE IF EXISTS Login"
  cursor.execute(query)
  
def retrieve_listener_details(cursor):
  username = input("Enter username of user you want to communicate with: ")
  query = f"""SELECT IP, PORT 
                FROM Login
                  WHERE Username='{username}'"""
  cursor.execute(query)
  for row in cursor.fetchall():
    return row   # ip, port of listener
  
def verify_initiator(cursor, auth_key):
  query = f"""SELECT Username 
                FROM Login
                  WHERE Auth_key='{auth_key}'"""
  cursor.execute(query)
  for _ in cursor.fetchall():
    return True   # initiator verified
  return False   # not there

def verify_username(cursor, username):
    query = f"""SELECT Username 
                FROM Login
                  WHERE Username='{username}'"""
    cursor.execute(query)
    for _ in cursor.fetchall():
      return True  
    return False  
  
def verify_password(cursor, username, pwd):
    query = f"""SELECT Username 
                FROM Login
                WHERE Username='{username}' AND Pwd='{pwd}' """
    cursor.execute(query)
    for _ in cursor.fetchall():
      return True 
    return False  

def update_login(cursor,username,auth_key,port):
  
  query = f"""
  UPDATE Login
  SET Auth_key = '{auth_key}', PORT = {port}
  WHERE Username = '{username}';
  """
  cursor.execute(query)
  
def update_logout(cursor,username):
  
  query = f"""
  UPDATE Login
  SET Auth_key = NULL, PORT = NULL
  WHERE Username = '{username}';
  """
  cursor.execute(query)

#   # write this in the server: 
# #define conection and cursor
# conn = sqlite3.connect("Servdata.sqlite")
# cursor = conn.cursor()
# # drop_table(cursor)
# create_table(cursor)
# while True:
#   ch=int(input("1. insert \n2. login \n3.logout \n4.retrieve listener \n5.verify initiator \n6. display \n7. exit \nEnter: "))
#   if(ch==1):
#     username=input("Enter username: ")
#     pwd=input("Enter pwd: ")
#     ip=input("Enter ip: ")
#     insert_table(username=username, cursor=cursor, pwd=pwd, ip=ip)
#     # conn.commit()
#   elif(ch==2):
#     username=input("Enter username: ")
#     auth_key=input("Enter auth_key: ")
#     p=int(input("Enter port: "))
#     update_login(cursor=cursor, username=username, auth_key=auth_key, port=p)
#     # conn.commit()
#   elif(ch==3):
#     username=input("Enter username: ")
#     update_logout(cursor=cursor, username=username)
#     # conn.commit()
#   elif(ch==4):
#     ip,port=retrieve_listener_details(cursor=cursor)
#     print(f"ip: {ip}      port: {port}")
#   elif(ch==5):
#     auth_key=input("Enter auth_key: ")
#     flag = verify_initiator(cursor=cursor, auth_key=auth_key)
#     if flag:
#       print("Verified")
#     else:
#       print("Not registered")
#   elif(ch==6):
#     display_table(cursor)
#   else:
#     break
# # Commit the changes and close the connection
# conn.commit()
# conn.close()

