# Packet Sniffer

![Screenshot](https://github.com/Lcsamarasinghe/Packet-Sniffer/blob/main/1.PNG)

## Project Description
Packet Sniffer is a simple yet powerful packet sniffing tool built with **Tkinter** for the graphical user interface (GUI) and **Scapy** for packet capture. This tool allows you to sniff **TCP** and **UDP** packets in real-time, displaying key packet details such as protocol, source IP, destination IP, and packet length in a professional table format.  
The application provides a clean and intuitive interface where users can easily start/stop packet sniffing and view the captured packet details in real-time.

## Features
- **Packet Sniffing**: Capture real-time **TCP** and **UDP** packets from the network.  
- **User-friendly GUI**: Built with **Tkinter**, making it easy to start/stop sniffing with a clean interface.  
- **Packet Details**: Displays important packet information including:
  - **Protocol type** (TCP/UDP)
  - **Source IP**
  - **Destination IP**
  - **Source Port**
  - **Destination Port**
  - **Packet Length** (in bytes)  
- **Clear Output**: A convenient button to clear the packet table and the output log.

## Installation

### Requirements
- **Python 3.x** or higher  
- **Scapy**: Required for packet sniffing.  
- **Tkinter**: Used for the GUI (typically bundled with Python).

### Installation Steps
Follow these steps to set up the project on your local machine:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/Packet-Sniffer.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd Packet-Sniffer
    ```

3. **Install the required dependencies**:
    ```bash
    pip install scapy
    ```

4. **Run the application**:
    ```bash
    python network_tools.py
    ```

## Dependencies
- **Scapy**: For packet sniffing. Install using:
    ```bash
    pip install scapy
    ```

- **Tkinter**: Tkinter is included by default with Python, but if it's missing, you can install it using:
    - **On Ubuntu/Linux**:
        ```bash
        sudo apt-get install python3-tk
        ```
    - **On Windows/macOS**: Tkinter is included by default with Python, no installation is required.
