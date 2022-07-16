from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from socket import socket, AF_INET, SOCK_STREAM,SHUT_RDWR
#prkey = ec.generate_private_key(ec.SECP256R1())
import sys
port = 1069
portca = 1036
hostname = "127.0.0.1"
if (len(sys.argv)==2):
    portca = int(sys.argv[1])
if (len(sys.argv)==3):
    portca = int(sys.argv[1])
    port = int(sys.argv[2])
if (len(sys.argv)==4):
    portca = int(sys.argv[1])
    port = int(sys.argv[2])
    hostname = sys.argv[3]
prkey = rsa.generate_private_key(65537,2048)
pukey = prkey.public_key()
com = x509.NameAttribute(NameOID.COMMON_NAME, u"Server")
cli = x509.Name([com])
bui = x509.CertificateSigningRequestBuilder()
bui = bui.subject_name(cli)
bui = bui.add_extension(x509.SubjectAlternativeName([x509.DNSName(u'localhost')]), critical=False)
csr = bui.sign(prkey, hashes.SHA384())
csr2 = csr.public_bytes(Encoding.PEM)
sock = socket(AF_INET, SOCK_STREAM)
sock.connect((hostname, portca))
#print(len(csr2))
#print(csr2)
sock.sendall(csr2)
certia = sock.recv(1000)
sock.sendall(b"ACK")
cacert = sock.recv(1000)
#print(cacert)
#print(certia)
cacert1 = x509.load_pem_x509_certificate(cacert)
certia1 = x509.load_pem_x509_certificate(certia)
sock.close()
print ("Certificate Exchange Done")
sock = socket()
sock.bind((hostname,port))
sock.listen()
algor = [b"Hello--TLS1.3--RSA--ChaCha-256--AES-128-GCM--SHA256", b"Hello--TLS1.3--RSA--ChaCha-256--AES-128-OCB3--SHA256"]
while 1:
    csock, chos= sock.accept()
    data = csock.recv(100000)
    algoi = data
    if data not in algor:
        csock.sendall(b"TERMINATE")
        csock.close()
        continue
    csock.sendall(certia)
    data = csock.recv(10000)
    if (data == b"TERMINATE"):
        csock.close()
        continue
    secert = x509.load_pem_x509_certificate(data)
    pubkey = secert.public_key()
    signa = secert.signature
    try:
        cacert1.public_key().verify(signa, secert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    except:
        csock.sendall(b"TERMINATE")
        csock.close()
        continue
    csock.sendall(b"ACK")
    enckey = csock.recv(10000)
    mskey = prkey.decrypt(enckey, padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None))
    csock.sendall(b"ACK")
    chac = ChaCha20Poly1305(mskey)
    nonc = csock.recv(12)
    enckey1 = csock.recv(10000)
    deckey = chac.decrypt(nonc, enckey1, None)
    csock.sendall(b"ACK")
    AESG = AESCCM(deckey)
    nonc = csock.recv(12)
    data = csock.recv(10000)
    data = AESG.decrypt(nonc, data, None)
    if data != (enckey1+b"--"+algoi):
        csock.sendall(b"TERMINATE")
        csock.close()
        continue
    csock.sendall(b"ACK")
    if csock.recv(10000) != b"ACK":
        csock.close()
        exit()
    print("Handshake Established")
    print("Starting message Exchange")
    nonc = os.urandom(12)
    csock.sendall(nonc)
    cipher = AESG.encrypt(nonc, b"The OTP for transferring Rs 1,00,000 to your friend's account is 256345.", None)

    csock.sendall(cipher)
    print ("Send Message - ")
    print("The OTP for transferring Rs 1,00,000 to your friend's account is 256345.")
    print("Record Protocol Ends and Closing Sockets")

    csock.shutdown(SHUT_RDWR)
    csock.close()