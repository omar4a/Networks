import tkinter as tk
import subprocess
import os
import sys
import threading
import sys

os.environ['PYDEVD_DISABLE_FILE_VALIDATION'] = '1'

if hasattr(sys, 'frozen'):
    sys.executable = sys.executable + ' -Xfrozen_modules=off'

class RedirectedOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)  # Scroll to the end

    def flush(self):
        pass

# Function to run a script
def run_script(script_name):
    def target():
        process = subprocess.Popen(['python', script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            print(line, end='')
        for line in process.stderr:
            print(line, end='')
    thread = threading.Thread(target=target)
    thread.start()

# Create the main window
root = tk.Tk()
root.title("DHCP Client")

# Set window size and background color
root.geometry("500x400")
root.configure(bg='black')

# Create a frame to hold the buttons
frame = tk.Frame(root, bg='black')
frame.pack(expand=True)

# Create a Text widget to display the output
output_text = tk.Text(root, wrap=tk.WORD, bg='black', fg='white', font=('Arial', 12, 'bold'))
output_text.pack(fill=tk.BOTH, expand=True)

# Redirect stdout to the Text widget
sys.stdout = RedirectedOutput(output_text)

# Dictionary of buttons with their respective script paths
buttons = {
    'ACK': 'Client_Ack.py',
    'Decline': 'Client_Decline.py',
    'Inform': 'Client_Inform.py',
    'NAK': 'Client_NAK.py'
}

# Define button properties
button_props = {
    'bg': 'white',
    'fg': 'black',
    'font': ('Arial', 14),
    'width': 8,  # Set uniform width for buttons
    'padx': 10,
    'pady': 5,
    'relief': tk.RAISED
}

# Create buttons using the full paths
for text, script in buttons.items():
    button = tk.Button(frame, text=text, command=lambda s=script: run_script(s), **button_props)
    button.pack(pady=10, ipadx=20, ipady=5)

# Run the GUI
root.mainloop()