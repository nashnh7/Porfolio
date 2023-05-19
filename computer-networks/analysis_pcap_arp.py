import socket
import dpkt
import binascii


def addColon(str):
    res = ""
    for i in range(0, len(str), 2):
        res += str[i:i + 2] + ":"

    res = res[:-1]
    return res

with open('assignment4_my_arp.pcap', 'rb') as f:
    # reads my wireshark pcap file
    pcap = dpkt.pcap.Reader(f)
    req = None
    res = None
    # initializes response request tuples

    for file, buf in pcap:

        ARPb = buf[12:14]
        if ARPb == b'\x08\x06':
            # checks for ARP packet

            if buf[20:22] == b'\x00\x01':
                # checks if it's a request, 1 means it is a request
                req_senderIP = socket.inet_ntoa(buf[28:32])
                req_senderMac = binascii.hexlify(buf[22:28]).decode()
                req_sM = addColon(req_senderMac)
                req_targetIP = socket.inet_ntoa(buf[38:42])
                req_targetM = binascii.hexlify(buf[32:38]).decode()
                req_tM = addColon(req_targetM)
                req = (req_senderIP, req_sM, req_targetIP, req_tM)

            if buf[20:22] == b'\x00\x02':
                # checks for a response, 2 opcode means it is a response
                res_senderIP = socket.inet_ntoa(buf[28:32])
                res_senderMac = binascii.hexlify(buf[22:28]).decode()
                res_sM = addColon(res_senderMac)
                res_targetIP = socket.inet_ntoa(buf[38:42])
                res_targetM = binascii.hexlify(buf[32:38]).decode()
                res_tM = addColon(res_targetM)
                res = (res_senderIP, res_sM, res_targetIP, res_tM)

            if req is not None and res is not None:
                print(
                    f'ARP Request: Sender IP: {req_senderIP}, Sender MAC: {req_sM}, Target IP: {req_targetIP}, Target MAC A: {req_tM}')
                print(
                    f'ARP Response: Sender IP: {res_senderIP}, Sender MAC: {res_sM}, Target IP: {res_targetIP}, Target MAC A: {res_tM}')
                print()

                res = None
                req = None
#               to prevent all requests and responses from being displayed
