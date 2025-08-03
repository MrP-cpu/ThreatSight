import threading
import time

done = False
counter = 0  # Initialize counter

def worker():
    global counter  # Declare counter as global since we're modifying it
    while not done:
        time.sleep(1)
        counter += 1
        print(counter)

# Create and start the thread

threading.Thread(target=worker, daemon=True).start()

# Wait for user input to stop
input("Press enter to quit\n")
done = True  # Signal the thread to stop

