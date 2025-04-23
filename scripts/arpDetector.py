from scapy.all import sniff  # Import sniffing function from Scapy

# Dictionary to map MAC addresses to their known IP addresses
IP_MAC_Map = {}

def processPacket(packet):
    # Check if the packet has an ARP layer
    if packet.haslayer("ARP"):
        # Extract source IP and source MAC from the ARP packet
        src_IP = packet['ARP'].psrc
        src_MAC = packet['Ether'].src

        # Check if this MAC address has already been seen
        if src_MAC in IP_MAC_Map:
            # If the MAC is mapped to a different IP than before it may be spoofing
            if IP_MAC_Map[src_MAC] != src_IP:
                old_IP = IP_MAC_Map[src_MAC]
                
                # Print a warning message about the potential ARP spoofing attack
                print("\n[!] Possible ARP Spoofing Attack Detected")
                print(f"    MAC {src_MAC} was previously mapped to {old_IP}, now claims to be {src_IP}")
        else:
            # If this is the first time seeing this MAC, store the IP-MAC mapping
            IP_MAC_Map[src_MAC] = src_IP

# Start sniffing ARP packets on the network
# - filter="arp" ensures only ARP packets are captured
# - store=0 prevents storing packets in memory (to save resources)
# - prn=processPacket tells Scapy to call our function for each packet
sniff(filter="arp", store=0, prn=processPacket)
