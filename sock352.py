import socket as syssock
import struct
import sys
import random
import time

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

# Yash Patel netid: ymp16
# Marcus Lomi netid: mal403

"""WE ARE KEEPING OUR VERSION OF SOCK352 AND ADDING IN THE NECESSARY COMPONENTS"""

global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT

# The communication box for encryption
global socketBox
global hostPrivateKey
global hostPublicKey
global partnerPublicKey
global receivePortNo

hostPrivateKey = -1
hostPublicKey = -1
partnerPublicKey = -1

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}



# this is 0xEC
ENCRYPT = 236

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
    global transmitPortNo
    transmitPortNo = int(UDPportTx)
    global receivePortNo
    receivePortNo = int(UDPportRx)

    udpSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    udpSocket.setsockopt(syssock.SOL_SOCKET, syssock.SO_REUSEADDR, 1)
    udpSocket.bind(('',int(UDPportRx)))  # using the global udpSocket to bind to the address
    print "Successfully bound to", UDPportRx

    if udpSocket is None:
        print "Could not create socket"
    else:
        print "Created socket"
    # binding is left for the bind method
    pass


class socket:
    address = ""  # Need to figure out if this is address of buddy or self

    def __init__(self):  # fill in your code here
        self.startSeqNo = None      # Current sequence number
        self.nextSeqNo = None
        self.expectedAck = None     # Expected acknowledgement no USED ONLY IN SYN DURING ACCEPT/CONNECT
        self.currentAck = None      # Current outgoing acknowledgement USED ONLY DURING ACCEPT/CONNECT
        self.connected = False
        self.partnerAddress = None  # Saved copy of partner's address
        self.encryption = False     # Saves whether or not the connection is encrypted
        return

    def bind(self, address):
        # Call bind
        return

    def connect(self, *args):  # This part is used by the client
        global socketBox
        global partnerPublicKey
        opt_flag = 0x0
        address = args[0]
        encrypt = None
        if len(args) > 1:
            print "Tuple size is big fam"
            encrypt = args[1]
            
        # When the destination is localhost we use the udpPortTX as the destination port for our message
        if address[0] == "localhost":
            address = ('127.0.0.1', transmitPortNo)
        else: # Keep the IP address specified by the user, just use UDPportTX
            adr = address[0]
            address = (adr, transmitPortNo)

        if encrypt is None:
            print "No encryption to be used"
        elif encrypt is not None:
            self.encryption = True
            opt_flag = 0x1
            print "Encrypting future payloads"

        self.partnerAddress = address
        print "Connecting to ", address

        # send the SYN packet a
        self.startSeqNo = random.randint(1, 64)
        h = header(0, SOCK352_SYN, self.startSeqNo, opt_flag)
        self.expectedAck = self.startSeqNo + 1

        udpSocket.sendto(h.data, address)  # Sending the first SYN

        # recv SYN ACK B
        while True:
            data, addr = udpSocket.recvfrom(8272)
            if data != None:
                headerDat = struct.unpack(sock352PktHdrData, data)
                print "\tServer Address:", addr
                print "\tReceived Server sequence no: Y = ", headerDat[8]
                # print "\tExpecting ACK=", self.expectedAck, "\n\tActual is: ACK=", headerDat[9]
                break

        # SYN (SEQ=x+1, ACK=y+1)
        # send ACK C
        self.currentAck = headerDat[8] + 1
        h = header(0, SOCK352_SYN, headerDat[9], opt_flag)
        h.setack_no(self.currentAck)  # Consider using a local variable to get the proper numbers
        print "Now sending ACK C SYN(seq=", h.sequence_no, " ACK=", h.ack_no, ")"
        udpSocket.sendto(h.data, address)
        self.startSeqNo = h.sequence_no + 1
        self.connected = True  # Connection established at this point

        # Setting up the encryption box for the client
        if self.encryption:
            for pubAddr in publicKeys:
                # Print pubAddr
                if pubAddr[0] == self.partnerAddress[0] and (pubAddr[1] == "*" or int(pubAddr[1]) == self.partnerAddress[1]):
                    print "Partner public Key set"
                    partnerPublicKey = publicKeys[pubAddr]
            if partnerPublicKey is None or partnerPublicKey == -1:  #This means that the partner public key isn't set. We'll assume its the default
                print "Had to resort to default public key"
                partnerPublicKey = hostPublicKey    # This is useful for connections from iLab to personal computer
            socketBox = Box(hostPrivateKey , partnerPublicKey)

        return

    def listen(self, backlog):
        print "Listening"  # No need to do anything for this yet
        return

    def accept(self, *args):
        global socketBox
        global partnerPublicKey
        print "Accepting..."
        if len(args) >= 1:
            if args[0] is ENCRYPT:
                self.encryption = True

        self.getPacket()

        # Setting up the encryption box for the server
        if self.encryption:
            for pubAddr in publicKeys:
                print "Checking value for", pubAddr
                if pubAddr[0] == self.partnerAddress[0] and (int(pubAddr[1]) == self.partnerAddress[1] or pubAddr[1] == "*"):
                    partnerPublicKey = publicKeys[pubAddr]
                    print "Partner public Key set"
            if partnerPublicKey is None or partnerPublicKey == -1:  # This means that the partner public key isn't set. We'll assume its the default
                partnerPublicKey = hostPublicKey
            socketBox = Box(hostPrivateKey,partnerPublicKey)
        print "Socketbox successfully created"

        (clientsocket, address) = (self, self.partnerAddress)
        return (clientsocket, address)

    def close(self):
        print("closing")
        if self.nextSeqNo is None:  # currently the client always has the nextSeqNo set to None
            print "Client tearing down connection"
            finHeader = header(0, SOCK352_FIN, 0, 0x0)
            udpSocket.sendto(finHeader.data, self.partnerAddress)
            print "\tWaiting for Ack..."
            data, addr = udpSocket.recvfrom(8272)
            finAck = struct.unpack(sock352PktHdrData, data)
            if finAck[1] == SOCK352_ACK:
                print "\t Received termination ack"
            self.getPacket()  # Now we wait for the server to do the same

        else:
            print "Server tearing down connection. Waiting first"
            self.getPacket()
            finHeader = header(0, SOCK352_FIN, 0, 0x0)
            udpSocket.sendto(finHeader.data, self.partnerAddress)
            print "Connection successfully terminated"

        # fin and ack, then close connection
        udpSocket.close()
        print "Connection closed"
        return

    def send(self, buffer):
        print "Sending data..."
        global socketBox
        encryptionFiller = 0
        if self.encryption:
            nonce = nacl.utils.random(Box.NONCE_SIZE)               # Create the nonce
            encryptedBuffer = socketBox.encrypt(buffer,nonce)       # Encrypt the payload
            h = header(len(encryptedBuffer)-40, 0x0, self.startSeqNo, 0x1)
            h.data += encryptedBuffer                               # Concatenate the buffer to the header data
        else:
            h = header(len(buffer), 0x0, self.startSeqNo, 0x0)  # tab this back in later
            h.data += buffer  # Our packet is simply the header data with the payload concatenated to it

        # print "\tPayload set: seq_no", self.startSeqNo
        udpSocket.sendto(h.data, self.partnerAddress)   # h.data is our actual packet.
        # It's just the header with the buffer added on
        # print "\tPayload sent"

        while True:
            # Waiting on Ack for packet we just sent
            try:
                udpSocket.settimeout(0.2)
                data, addr = udpSocket.recvfrom(8272)
                headerDat = struct.unpack(sock352PktHdrData, data)  # receive the incoming header data from the client
                print "\tACK received:", headerDat[9]               # check the SYN flag in the header
                while headerDat[9] != self.startSeqNo:              # If we get back an incorrect ack
                    print "Bad ACK received"
                    udpSocket.sendto(h.data, self.partnerAddress)  # Resend the packet and let the loop go again
                    data, addr = udpSocket.recvfrom(8272)
                    headerDat = struct.unpack(sock352PktHdrData,
                                              data)  # receive the incoming header data from the client\
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
        global socketBox
        newpacket = self.getPacket()  # go poll for new packets and return them
        while (newpacket is not None) and newpacket.packetHeader[8] != self.nextSeqNo:
            print "Didn't get the expected sequence number which is,", self.nextSeqNo
            newpacket = self.getPacket()
        while newpacket is None:  # While get packet keeps returning None, keep waiting for new packets.
            # Client will always send new ones
                newpacket = self.getPacket()  # got a bad packet, trying to get a new one
        print "Packet Received"
        self.nextSeqNo += 1
        # print "Payload size is:", newpacket.packetHeader[11], "nybytes is:", nbytes
        if newpacket.packetHeader[2] == 0x1:    # If the packet was encrypted we decrypt it here
            bytesreceived = socketBox.decrypt(newpacket.payload)
        else:       # It's a regular packet
            bytesreceived = newpacket.payload

        return bytesreceived

    def getPacket(self):
        print "Waiting for incoming packets..."

        # This method will act as an abstraction layer for retrieving a packet from the sender
        packetData, addr = udpSocket.recvfrom(8272)      # Get the packet data
        rawheader = packetData[0:40]  # Isolate the header
        receivedheader = struct.unpack(sock352PktHdrData, rawheader)  # Unpack the header
        opt_flag = 0x0

        # print "PAYLOAD SIZE", receivedheader[11]
        if self.encryption:         # If the connection is encrypted then we set the flag
            opt_flag = 0x1

        if receivedheader[1] == SOCK352_SYN:             # If we receive a SYN flag
            if self.startSeqNo is None:
                self.startSeqNo = random.randint(0, 64)  # Create the new sequence_no
            if self.connected is True:
                sendheader = header(0, SOCK352_RESET, self.startSeqNo, opt_flag)
            else:
                sendheader = header(0, SOCK352_SYN, self.startSeqNo, opt_flag)  # Create the header we want to send
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
                packetData, addr = udpSocket.recvfrom(8272)
                rawheader = packetData[0:40]                                  # Isolate the header
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
            ackHeader = header(0, SOCK352_ACK, 0, opt_flag)
            udpSocket.sendto(ackHeader.data, self.partnerAddress)
            return None

        elif receivedheader[1] == 0x0:          # Regular data packet
            print "\tRegular data packet"
            p = packet()                        # Create the new blank packet object
            p.packetHeader = receivedheader     # Set the packet header to the unpacked data we received

            p.payload = packetData[40:]                     # Set the payload to the raw data minus the header data
            h = header(0, SOCK352_ACK, self.startSeqNo, opt_flag)     # Create a new header of payload zero as our acknowledgment
            h.setack_no(receivedheader[8])                  # The acknowledgement number is the sequence number we got
            udpSocket.sendto(h.data, self.partnerAddress)   # Send over the acknowledgement
            print "\tSent acknowledgement for packet no:", receivedheader[8]
            return p
        else:
            print "Corrupted packet"
            return None  # Returning None will trigger a repeated method call in recv()

        pass

def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys
    global hostPrivateKey
    global hostPublicKey

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    if host == "localhost":  # Changing localhost to an IP
                        host = "127.0.0.1"
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                        if host == '*' and port == '*':
                            print "Host Private key set"
                            hostPrivateKey = privateKeys[(host, port)]
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
                        if host == '*' and port == '*':
                            print"Default public key used"
                            hostPublicKey = publicKeys[(host, port)]
        except Exception, e:
            print ("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print ("error: No filename presented")

    return (publicKeys, privateKeys)

# Class header to organize the code and have an object that can easily be created with the parameters we need
class header:
    # This class has member variables for every header variable
    # There are also other methods to reset certain field values from the default and repack the data
    def __init__(self, length, flags, sequence_no, opt):
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        self.version = 0x1  # [0]
        self.flags = flags  # [1]
        if opt:
            self.opt_ptr = opt  # [2] encryption flag, if encrypted set to 0x1
        else:
            self.opt_ptr = 0x0
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

    def setOptField(self, number):
        self.opt_ptr = number
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
