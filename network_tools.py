import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Packet Sniffer")
        self.root.geometry("800x400")

        # === Control Panel ===
        control_frame = ttk.Frame(root)
        control_frame.pack(pady=10, padx=10, fill="x")

        # Start Sniffing Button
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        # Stop Sniffing Button
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        # Clear Output Button
        self.clear_button = ttk.Button(control_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=2, padx=5)

        # === Packet Table ===
        self.packet_tree = ttk.Treeview(root, columns=("Protocol", "Source IP", "Destination IP", "Length"), show="headings")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Source IP", text="Source IP")
        self.packet_tree.heading("Destination IP", text="Destination IP")
        self.packet_tree.heading("Length", text="Length")

        self.packet_tree.column("Protocol", width=100)
        self.packet_tree.column("Source IP", width=150)
        self.packet_tree.column("Destination IP", width=150)
        self.packet_tree.column("Length", width=100)

        self.packet_tree.pack(padx=10, pady=10, fill="both", expand=True)

        # === Output Display (Scrolled Text) ===
        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=10)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.sniffing = False  # State to control sniffing

    def start_sniffing(self):
        """Start the packet sniffing in a separate thread."""
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True  # Daemon thread will close with the app
        thread.start()

    def stop_sniffing(self):
        """Stop the packet sniffing."""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def clear_output(self):
        """Clear both the packet table and the output text area."""
        # Clear the table
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Clear the output text box
        self.output.delete('1.0', tk.END)

    def sniff_packets(self):
        """Capture and process packets."""
        
        def process_packet(packet):
            """Filter and display packets based on protocol."""
            if IP in packet:
                proto = None
                # Determine the protocol
                if TCP in packet:
                    proto = "TCP"
                elif UDP in packet:
                    proto = "UDP"
                else:
                    return  # Ignore other protocols

                # Add packet to the table
                self.packet_tree.insert("", "end", values=(proto, packet[IP].src, packet[IP].dst, len(packet)))

                # Display formatted message in the text box
                msg = f"[{proto}] {packet[IP].src} → {packet[IP].dst} | Length: {len(packet)}\n"
                self.output.insert(tk.END, msg)
                self.output.see(tk.END)

        # Start sniffing packets continuously
        sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.sniffing)


# === Main Execution ===
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
