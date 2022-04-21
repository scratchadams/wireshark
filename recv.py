from scapy.all import *

data = []

def recv_data(pkt):
    data.append('{:02x}'.format(pkt[2].code))
    data.append('{:04x}'.format(pkt[2].id))
    data.append('{:04x}'.format(pkt[2].seq))

sniff(filter="host 10.0.0.182 and icmp", prn=recv_data)

with open("test.elf", "wb") as f:

    for x in data:
        f.write(bytes.fromhex(x))


