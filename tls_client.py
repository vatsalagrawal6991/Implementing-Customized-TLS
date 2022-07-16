import ssl
from pprint import pprint
from sys import argv
from socket import socket, AF_INET, SOCK_STREAM,SHUT_RDWR
port = 443
con = True
hostname = "www.w3schools.com"
path = "images/picture.jpg"
if (len(argv)==2):
	hostname = argv[1]
	path = ""
if (len(argv)==3):
	hostname = argv[1]
	path = ""
	con = argv[2]
	if con == "True":
		con = True
	else:
		con = False
if (len(argv)==4):
	hostname = argv[1]
	con = argv[2]
	path = argv[3]
	if con =="True":
		con =True
	else:
		con = False
cadir = './certs'
print ("Cadir Folder path:")
print (cadir)
print ("Check Hostname Attribute:")
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cafile="./certs/ca-certificates.crt", capath = cadir)
#context.load_verify_locations(capath = cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = con
print(context.check_hostname)

sock = socket(AF_INET, SOCK_STREAM)
sock.connect((hostname,port))
input("After making TCP connection. Press any key to continue ......")

ssock = context.wrap_socket(sock, server_hostname = hostname, do_handshake_on_connect= False)
ssock.do_handshake()
pprint(ssock.getpeercert())
input("After getpercert. Press any key to continue ......")
pprint(ssock.cipher())
input("After cipher. Press any key to continue ......")

request = b"GET /" + path.encode('utf-8') + b" HTTP/1.0\r\nHost: " + hostname.encode('utf-8') + b"\r\n\r\n"
pprint(request.split(b"\r\n"))
ssock.sendall(request)

response = ssock.recv(2048)
while response:
	pprint(response.split(b"\r\n"))
	response = ssock.recv(2048)

ssock.shutdown(SHUT_RDWR)
ssock.close()
