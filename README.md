Packet Sniffer

Project Description
Packet Sniffer is a simple packet sniffing tool built using Tkinter for the graphical user interface (GUI) and Scapy for packet capture. This tool allows you to sniff TCP and UDP packets in real-time, displaying packet details such as protocol, source IP, destination IP, and packet length in a professional table format.

The application provides a clean and easy-to-use interface, where users can start/stop packet sniffing and view the captured packets with their corresponding details.

Features
Packet Sniffing: Capture real-time TCP and UDP packets from the network.

User-friendly GUI: Built with Tkinter, providing a simple interface to start and stop sniffing.

Packet Details: Displays details such as protocol type, source IP, destination IP, source port, destination port, and packet length.

Clear Output: Option to clear the output logs and the packet table.

Installation
Requirements
Python 3.x or higher

Scapy: For packet sniffing

Tkinter: For the GUI (usually bundled with Python)

Installation Steps
Clone this repository:

bash
Copy code
git clone https://github.com/YOUR_USERNAME/Packet-Sniffer.git
Navigate to the project directory:

bash
Copy code
cd Packet-Sniffer
Install the required dependencies:

bash
Copy code
pip install scapy
Run the application:

bash
Copy code
python network_tools.py
Dependencies
Scapy:

bash
Copy code
pip install scapy
Tkinter: Tkinter is included with Python by default. If it's missing, you can install it as follows:

On Ubuntu/Linux:

bash
Copy code
sudo apt-get install python3-tk
On Windows/macOS: Tkinter comes bundled with Python, so no installation is required.

Usage
Once the application starts, you will see the following options in the GUI:

Start Sniffing: Begins capturing TCP/UDP packets.

Stop: Stops the packet sniffing process.

Clear Output: Clears both the packet table and the output text area.

Packets will be displayed in the table with the following details:

Protocol: TCP/UDP

Source IP

Destination IP

Packet Length: Size of the packet in bytes
