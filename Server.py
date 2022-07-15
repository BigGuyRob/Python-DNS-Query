import socket
import binascii
import argparse
from sys import argv
google_dns = "8.8.8.8"
udp_port = 53
HEXBYTE = 4 #This is equal to 2 BYTES = 16 bits = 1 line from the header
#16 bits in hex
ID = 'acdc' #1010 1100 1101 1100
qP = '' #0000 0001 0000 0000
QR = 0 #Query 0 1 bit
OPCODE = 0000  #Standard Query 4 bits
AA = 0 #1 bit each for the following parameters
TC = 0 
RD = 1 
RA = 0 
Z = 000 #3 bits
RCODE = 0000 #4 bits
QUERYPARAMETERS = "0100"
#Query Parameters will total 16 bits
#NOTE: ZFILL IS REQUIRED IN ORDER TO KEEP 0s, otherwise 00000 as an int is equal to 0 and we lose the MSBs
#Header is the ID in binary + query parameters + the other 4 fields 
ANCOUNT = '0000' #Number of answers
NSCOUNT = '0000' #number of authority records
ARCOUNT = '0000' #number of additional records
QDCOUNT = '0001' #Number of quesitons
Header = ID + QUERYPARAMETERS + QDCOUNT +  ANCOUNT + NSCOUNT+ ARCOUNT

#FOR THE QUESTION
TERMINATOR = '00'
QTYPE = '0001' #A record = 1
QCLASS = '0001' #internet class = 1

#We want it to look like the string from the article
#This function takes our string ip, seperates it into fields with labels, and encodes it in HEX
def encodeQuestion(ipAddy):
    labels = ipAddy.split(".")
    ret = ""
    for label in labels:
        labelLength = len(label)
        hl = hex(labelLength)
        labelLength = hl.replace("x", "")
        ret += labelLength
        for ch in label:
            hexChar = format(ord(ch), "x")
            if ch.isdigit(): 
                hexChar = hex(int(ch))
                hexChar = hexChar.replace("x","")
            ret += hexChar
    ret+= TERMINATOR
    ret+=QTYPE
    ret+=QCLASS
    return (ret)

#This is a recursive function to decode the response
#Makes calls to createIPfromHEX and parseLabel
def decodeResponse(response,pickup):
    nextBYTE = response[pickup: pickup + 2*HEXBYTE]
    if(nextBYTE == ''):
        return ''
    pickup = pickup + HEXBYTE #SKIP PRIOR OCCURENCE OF NAME
    ATYPE = response[pickup:pickup + HEXBYTE]
    pickup = pickup + HEXBYTE + HEXBYTE #AHEAD FOR TYPE and SKIPPING CLASS 
    pickup = pickup + 2*HEXBYTE #SKIP TTL
    RDLENGTH = response[pickup:pickup+HEXBYTE]
    pickup = pickup + HEXBYTE
    IP,pickup = parseLabel(response, pickup, RDLENGTH, "ANSWER")
    ret=""
    if ATYPE != '0001': #We will skip records that are not A records
        return decodeResponse(response[pickup:len(response)],0)
    else:
        ret = creatIPfromHEX(IP) + "," + decodeResponse(response[pickup:len(response)],0)
    return ret.rstrip(",")

#This is a function that takes in the bytes corresponding to a question or answer NAME field
#Since we know we have one byte labels for question NAME field and two byte labels for answer
# It is easy enough to use the same method for both, but only run it once for the answer
# since the labels are different sizes
# Basically this method: Picks up right after the label and grabs the entire name at once, for questions where the label length is always 2
# This method has a while() in order to parse the entire Name at once by treating the next two bytes after the end of the name as the next label.
# (Note: We believe this functionality is useful because it is used to parse any NAME field, even though not necessarily for this project)
# The while is negated for answer since this is functionality is achieved using recursion 
def parseLabel(response, pickup, byte, type):
    NAME = ''
    while(byte != '00'):
         #so we know this will fire, if the type we are decoding is a response we will simply stop after one round
        try:
            nameLength = int(byte, 16)
        except ValueError:
            return (NAME,pickup)
        NAME += response[pickup:(pickup + nameLength * 2)]
        nextByteLocation = (pickup + nameLength * 2)
        byte = response[nextByteLocation:nextByteLocation + 2]
        if(type == "ANSWER"):
            #do nothing bc we want it to run once
            pickup = nextByteLocation
            return (NAME, pickup)
        else:
            pickup = (nextByteLocation + 2)
    return(NAME, pickup)

#This function takes the known IP Schema in HEX, which is XX:XX:XX:XX     
def creatIPfromHEX(IP):
    return str(int(IP[0:2],16)) + "." + str(int(IP[2:4],16)) + "." +  str(int(IP[4:6],16)) + "." +  str(int(IP[6:8],16))

#------------------MAIN SCRIPT-------------------
#Set up the arg parser and args
parser = argparse.ArgumentParser(description="""This server program allows data read to be converted to a DNS message and prints the responses to another text file""")
parser.add_argument('port', type=int, help='This is the port number for the client to connect to')
args = parser.parse_args(argv[1:])
PORT = args.port
#Set up the sockets
tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcpSocket.bind(('',PORT))
print(f'TCP Socket created and bound to {PORT}')
#Look for connection from client
tcpSocket.listen()
conn,addr = tcpSocket.accept()
print(f'{addr} has connected to {PORT}')
#Get some data
data= conn.recv(4096)
#Deal with the data
while(data): 
    domain = data.decode('utf-8')
    print(domain)
    #Use the encoding message function to take the domain name -> HEX DNS schema
    hexMessage = encodeQuestion(domain)
    message = Header + hexMessage
    #Make an attempt to send this DNS message to google
    try:
        serverAddress = (google_dns, udp_port)
        s.sendto(binascii.unhexlify(message), serverAddress)
        dt = "temp"
        msg = ""
        #Recieve our answers
        while(dt):
            dt, addr = s.recvfrom(4096)
            msg +=binascii.hexlify(dt).decode("utf-8")
            dt = ""
    except socket.timeout:
        print("No Good (DNS Server Timed Out)")
    #Decode the answer given for this domain
    #Since we know that the header is 24 bits total we can skip it and send in the address of the first byte we care about
    pickup = 24
    hdr = msg[:23]
    byte = msg[pickup:pickup+2]
    pickup +=2
    NAME = ""
    NAME,pickup = parseLabel(msg,pickup,byte,"question")
    pickup = pickup + HEXBYTE + HEXBYTE #skip QTYPE and QCLASS
    #NOW we are at the beginning of the ANSWER portion at pickup
    RESPONSE = decodeResponse(msg, pickup)
    #Print the responses for the user of server
    print(RESPONSE)
    #Send the info back to the client to put into file
    conn.sendall(RESPONSE.encode('utf-8'))
    data = conn.recv(1024)
#Once all of the data has been read from the client, close both ports as the program has completed. 
tcpSocket.close()
s.close()
#Close the UDP socket and the TCP socket once the program is over