#######################################################################################################################
# Author: Maurice Snoeren                                                                                             #
# Version: 0.1 beta (use at your own risk)                                                                            #
#                                                                                                                     #
# This example show how to create your own peer 2 peer network using the callback. So, you do not need to implement   #
# a new class. However, it is adviced to implement your own class rather than use the callback. Callback will get you #
# a big and large method implementation.                                                                              #
#######################################################################################################################

import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from p2pnetwork.node import Node

# The big callback method that gets all the events that happen inside the p2p network.
# Implement here your own application logic. The event holds the event that occurred within
# the network. The main_node contains the node that is handling the connection with and from
# other nodes. An event is most probably triggered by the connected_node! If there is data
# it is represented by the data variable.
def node_callback(event, main_node, connected_node, data):
    try:
        if event != 'node_request_to_stop': # node_request_to_stop does not have any connected_node, while it is the main_node that is stopping!
            print(f"Recieved: {data}\n")

    except Exception as e:
        print(e)

# Just for test we spin off multiple nodes, however it is more likely that these nodes are running
# on computers on the Internet! Otherwise we do not have any peer2peer application.
node_1 = Node("10.0.2.15", 10200, callback=node_callback)   

time.sleep(1)
#node_1.debug = True
#node_2.debug = True
#node_3.debug = True
node_1.start()
time.sleep(1)

node_1.connect_with_node('10.52.1.147', 10200)

time.sleep(2)

# node_1.send_to_nodes("message: Hi from DISHA")

# time.sleep(5)

node_1.stop()

print('end')