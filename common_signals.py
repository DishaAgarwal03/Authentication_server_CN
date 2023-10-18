import threading

# Create separate events for each peer
ready_signala = threading.Event()
ready_signalb = threading.Event()