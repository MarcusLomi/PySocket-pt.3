import socket as syssock
import struct
import sys
import random
import time

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

# Yash Patel netid: ymp16
# Marcus Lomi netid: mal403

# FLAGS
SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0

sock352PktHdrData = "!BBBBHHLLQQLL"  # Setting up the packet header data for the socket
udpPkt_hdr_data = struct.Struct(sock352PktHdrData)

def init(UDPportTx, UDPportRx):  # initialize your UDP socket here

    global udpSocket
    global intConversion

    udpSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    if (udpSocket is None):
        print "Could not create socket"
    else:
        print "Created socket"
    #binding is left for the bind method
    pass


class socket:
    address = ""  # Need to figure out if this is address of buddy or self

    def __init__(self):  # fill in your code here
        self.startSeqNo = None          # Current sequence number
        self.nextSeqNo = None
        self.expectedAck = None         # Expected acknowledgement no USED ONLY IN SYN DURING ACCEPT/CONNECT
        self.currentAck = None          # Current outgoing acknowledgement USED ONLY DURING ACCEPT/CONNECT
        self.connected = False
        self.partnerAddress = None      # Saved copy of partner's address
        return

    def bind(self, address):
        print "Binding to address ", address
        # Call bind
        udpSocket.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)
        udpSocket.bind(address)  # using the global udpSocket to bind to the address
        return

    def connect(self, address):  # This part is used by the client
        #print "Connecting..."
        self.partnerAddress = address
        # Create SYN header
        # send the SYN packet a
        self.startSeqNo = random.randint(1, 64)
        #print "\tSending random sequence number SYN(x=", self.startSeqNo, ")"
        h = header(0, SOCK352_SYN, self.startSeqNo)
        self.expectedAck = self.startSeqNo + 1
        udpSocket.sendto(h.data, address)       # Sending the first SYN

        # recv SYN ACK B
        while True:
            data, addr = udpSocket.recvfrom(8232)
            if data != None:
                headerDat = struct.unpack(sock352PktHdrData, data)
                print "\tServer Address:", addr
                print "\tReceived Server sequence no: Y = ", headerDat[8]

                #print "\tExpecting ACK=", self.expectedAck, "\n\tActual is: ACK=", headerDat[9]
                break

        # SYN (SEQ=x+1, ACK=y+1)
        # send ACK C
        self.currentAck = headerDat[8] + 1
        h = header(0, SOCK352_SYN, headerDat[9])
        h.setack_no(self.currentAck)  # Consider using a local variable to get the proper numbers
        print "Now sending ACK C SYN(seq=", h.sequence_no, " ACK=", h.ack_no, ")"
        udpSocket.sendto(h.data, address)
        self.startSeqNo = h.sequence_no + 1
        self.connected = True               # Connection established at this point
        # if there is error send header again | FINISH LATER

        return

    def listen(self, backlog):
        print "Listening"  # No need to do anything for this yet
        return

    def accept(self):
        print "Accepting..."
        self.getPacket()
        # need to handle situation where there is already a connection
        (clientsocket, address) = (self, self.partnerAddress)

        return (clientsocket, address)

    def close(self):  # fill in your code here
        print("closing")
        if self.nextSeqNo is None:  # currently the client always has the nextSeqNo set to None
            print "Client tearing down connection"
            finHeader = header(0, SOCK352_FIN, 0)
            udpSocket.sendto(finHeader.data, self.partnerAddress)
            print "\tWaiting for Ack..."
            data, addr = udpSocket.recvfrom(8232)
            finAck = struct.unpack(sock352PktHdrData, data)
            if finAck[1] == SOCK352_ACK:
                print "\t Received termination ack"
            self.getPacket()        # Now we wait for the server to do the same

        else:
            print "Server tearing down connection. Waiting first"
            self.getPacket()
            finHeader = header(0, SOCK352_FIN, 0)
            udpSocket.sendto(finHeader.data, self.partnerAddress)
            print "Connection successfully terminated"

        # fin and ack, then close connection
        udpSocket.close()
        print "Connection closed"
        return

    def send(self, buffer):
        print "Sending data..."

        h = header(len(buffer), 0x0, self.startSeqNo)
        h.data += buffer            # Our packet is simply the header data with the payload concatenated to it

        # print "\tPayload set: seq_no", self.startSeqNo
        udpSocket.sendto(h.data, self.partnerAddress)
        # print "\tPayload sent"

        while True:
            # Ack for packet we just sent
            try:
                udpSocket.settimeout(0.2)
                data, addr = udpSocket.recvfrom(8232)
                headerDat = struct.unpack(sock352PktHdrData, data)  # receive the incoming header data from the client
                print "\tACK received:", headerDat[9]  # check the SYN flag in the header
                while headerDat[9] != self.startSeqNo:     # If we get back an incorrect ack
                    print "Bad ACK received"
                    udpSocket.sendto(h.data, self.partnerAddress)   # Resend the packet and let the loop go again
                    data, addr = udpSocket.recvfrom(8232)
                    headerDat = struct.unpack(sock352PktHdrData,data)  # receive the incoming header data from the client\
                    if headerDat[1] == SOCK352_ACK and headerDat[9] == self.startSeqNo:
                       self.startSeqNo += 1
                       break
                if headerDat[1] == SOCK352_ACK and headerDat[9] == self.startSeqNo:
                    self.startSeqNo += 1
                    print "\tPacket arrived successfully to receiver"
            except syssock.timeout:
                print "Resending packet seq_no", self.startSeqNo
                udpSocket.sendto(h.data, self.partnerAddress)
            finally:
                udpSocket.settimeout(None)
                break

        bytesent = len(buffer)
        return bytesent

    def recv(self, nbytes):
        print "Receiving data..."

        newpacket = self.getPacket()  # go poll for new packets and return them
        while (newpacket is not None) and newpacket.packetHeader[8] != self.nextSeqNo:
            print "Didn't get the expected sequence number which is,", self.nextSeqNo
            newpacket = self.getPacket()
            if newpacket is None:
                newpacket = self.getPacket()    # got a bad packet, trying to get a new one
        print "Packet Received"
        self.nextSeqNo += 1
        #print "Payload size is:", newpacket.packetHeader[11], "nybytes is:", nbytes

        # Next we decode the header to see what the payload size was
        bytesreceived = newpacket.payload

        # Add a get packet abstraction here
        return bytesreceived

    def getPacket(self):
        print "Waiting for incoming packets..."

        # This class will act as an abstraction layer for retrieving a packet from the sender
        packetData, addr = udpSocket.recvfrom(8232)  # Get the packet data
        rawheader = packetData[0:40]  # Isolate the header
        receivedheader = struct.unpack(sock352PktHdrData, rawheader)  # Unpack the header

        #print "PAYLOAD SIZE", receivedheader[11]
        if receivedheader[1] == SOCK352_SYN:             # If we receive a SYN flag
            if self.startSeqNo is None:
                self.startSeqNo = random.randint(0, 64)  # Create the new sequence_no
            if self.connected is True:
                sendheader = header(0, SOCK352_RESET, self.startSeqNo)
            else:
                sendheader = header(0, SOCK352_SYN, self.startSeqNo)  # Create the header we want to send
            self.expectedAck = self.startSeqNo + 1
            self.currentAck = int(receivedheader[8]) + 1

            sendheader.setack_no(self.currentAck)
            print "\tServer seq", self.startSeqNo, "Server ACK B", self.currentAck

            # send SYN(seq=y, ACK = x+1)
            print "\tSending SYN ACK B"
            udpSocket.sendto(sendheader.data, addr)
            try:
                print "\tSent. Now receiving ACK C"
                udpSocket.settimeout(0.2)
                packetData, addr = udpSocket.recvfrom(8232)
                rawheader = packetData[0:40]  # Isolate the header
                receivedheader = struct.unpack(sock352PktHdrData, rawheader)  # Unpack the header

                if receivedheader[8] == self.currentAck and receivedheader[9] == self.startSeqNo + 1:
                    print "Connection confirmed \n seq=", self.currentAck, "ACK=", receivedheader[9]
                    self.connected = True
                    self.currentAck += 1
                    self.startSeqNo += 1
                    self.nextSeqNo = receivedheader[8] + 1
                    self.partnerAddress = addr
                    udpSocket.settimeout(None)
                    return

            except syssock.timeout:
                udpSocket.sendto(sendheader.data, addr)
            finally:
                udpSocket.settimeout(None)

        elif receivedheader[1] == SOCK352_FIN:
            print "Received FIN, Sending Confirmation ACK"
            ackHeader = header(0, SOCK352_ACK, 0)
            udpSocket.sendto(ackHeader.data, self.partnerAddress)
            return None

        elif receivedheader[1] == 0x0:
            print "\tRegular data packet"
            p = packet()  # Create the new blank packet object
            p.packetHeader = receivedheader  # Set the packet header to the unpacked data we received

            p.payload = packetData[40:]  # Set the payload to the raw data minus the header data
            h = header(0, SOCK352_ACK, self.startSeqNo)  # Create a new header of payload zero as our acknowledgment
            h.setack_no(receivedheader[8])  # The acknowledgement number is the sequence number we got
            udpSocket.sendto(h.data, self.partnerAddress)  # Send over the acknowledgement
            print "\tSent acknowledgement for packet no:", receivedheader[8]
            return p
        else:
            print "Corrupted packet"
            return None         # Returning none will trigger a repeated method call in recv()

        pass


# Class header to organize the code and have an object that can easily be created with the parameters we need
class header:
    # This class has member variables for every header variable
    # There are also other methods to reset certain field values from the default and repack the data
    def __init__(self, length, flags, sequence_no):
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        self.version = 0x1  # [0]
        self.flags = flags  # [1]
        self.opt_ptr = 0x0  # [2] ignored for part 1
        self.protocol = 0x0  # [3] ignored for part 1
        self.header_len = sys.getsizeof(sock352PktHdrData)  # [4]
        self.checksum = 0x0  # [5] ignored for part 1
        self.source_port = 0x0  # [6] ignored for part 1
        self.dest_port = 0x0  # [7] ignored for part 1
        self.sequence_no = sequence_no  # [8]
        self.ack_no = 0x0  # [9]
        self.window = 0x0  # [10] ignored for part 1
        self.payload_len = length  # [11]

        self.data = udpPkt_hdr_data.pack(self.version, self.flags, self.opt_ptr, self.protocol,
                                         self.header_len, self.checksum, self.source_port, self.dest_port,
                                         self.sequence_no, self.ack_no, self.window, self.payload_len)

    def repack(self):
        self.data = udpPkt_hdr_data.pack(self.version, self.flags, self.opt_ptr, self.protocol,
                                         self.header_len, self.checksum, self.source_port, self.dest_port,
                                         self.sequence_no, self.ack_no, self.window, self.payload_len)

    def setsequence_no(self, number):
        self.sequence_no = number
        self.repack()

    def setack_no(self, number):
        self.ack_no = number
        self.repack()

# Packet class used mainly in getPacket() method
class packet:
    def __init__(self):
        self.packetHeader = None
        self.payload = None

    def setheader(self, packetHeader):
        self.packetHeader = packetHeader
        return

    def setpayload(self, payload):
        self.payload = payload
        return

    def getpacketheader(self):
        return self.packetHeader
