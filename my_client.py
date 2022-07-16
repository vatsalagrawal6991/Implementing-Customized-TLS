from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
from socket import socket, AF_INET, SOCK_STREAM,SHUT_RDWR
import os
import sys
ports = 1069
portc = 1056
portca = 1036
hostname = "127.0.0.1"
if (len(sys.argv)==3):
    portca = int(sys.argv[1])
    ports = int(sys.argv[2])
if (len(sys.argv)==4):
    portca = int(sys.argv[1])
    ports = int(sys.argv[2])
    portc = int(sys.argv[3])
if (len(sys.argv)==5):
    portca = int(sys.argv[1])
    ports = int(sys.argv[2])
    portc = int(sys.argv[3])
    hostname = sys.argv[4]
#prkey = ec.generate_private_key(ec.SECP256R1())
prkey = rsa.generate_private_key(65537,2048)
pukey = prkey.public_key()
com = x509.NameAttribute(NameOID.COMMON_NAME, u"Vatsal")
cli = x509.Name([com])
bui = x509.CertificateSigningRequestBuilder()
bui = bui.subject_name(cli)
bui = bui.add_extension(x509.SubjectAlternativeName([x509.DNSName(u'localhost')]), critical=False)
csr = bui.sign(prkey, hashes.SHA256())
csr2 = csr.public_bytes(Encoding.PEM)
sock = socket(AF_INET, SOCK_STREAM)
sock.connect((hostname,portca))
#print(len(csr2))
#print(csr2)
sock.sendall(csr2)
certia = sock.recv(10000)
sock.sendall(b"ACK")
certia1 = x509.load_pem_x509_certificate(certia)
cacert = sock.recv(10000)
cacert1 = x509.load_pem_x509_certificate(cacert)
#print(certia)
#print(len(cacert))
sock.close()
print ("Certificate Exchange Done")
sock = socket(AF_INET, SOCK_STREAM)
sock.connect((hostname,ports))
sock.sendall(b"Hello--TLS1.3--RSA--ChaCha-256--AES-128-GCM--SHA256")
data = sock.recv(10000)

if (data == b"TERMINATE"):
    sock.close()
    exit()

secert = x509.load_pem_x509_certificate(data)
pubkey = secert.public_key()
signa = secert.signature
try:
    cacert1.public_key().verify(signa, secert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
except:
    sock.sendall(b"TERMINATE")
    sock.close()
    exit()
sock.sendall(certia)
data = sock.recv(10000)
if (data == b"TERMINATE"):
    sock.close()
    exit()
#veri = cacert1.public_key().verifier(secert.signature, padding.PSS(padding.MGF1(hashes.SHA256()),padding.PSS.MAX_LENGTH),hashes.SHA256())
#veri.update(secert.tbs_certificate_bytes)
#veri.verify()
aekey = AESCCM.generate_key(128)
chkey = ChaCha20Poly1305.generate_key()
enckey = pubkey.encrypt(chkey,padding.OAEP(padding.MGF1(hashes.SHA256()),hashes.SHA256(),None))
sock.sendall(enckey)
if sock.recv(10000) != b"ACK" :
    sock.close()
    exit()

cha = ChaCha20Poly1305(chkey)
nonc = os.urandom(12)
cipher = cha.encrypt(nonc, aekey,None)
sock.sendall(nonc)
sock.sendall(cipher)

if sock.recv(10000) != b"ACK" :
    sock.close()
    exit()

AESG = AESCCM(aekey)
nonc = os.urandom(12)
cipher = AESG.encrypt(nonc, (cipher+b"--"+b"Hello--TLS1.3--RSA--ChaCha-256--AES-128-GCM--SHA256"),None)
sock.sendall(nonc)

sock.sendall(cipher)
if sock.recv(10000) != b"ACK" :
    sock.close()

    exit()
sock.sendall(b"ACK")
print("Handshake Established")
print("Starting message Exchange")
nonc = sock.recv(12)
data = sock.recv(10000)
text = b""
#sock.setblocking(False)
while data:
    text = text + data
    data = sock.recv(10000)
#print("Received Message -")
text = AESG.decrypt(nonc, text, None)

print("Received Message -")
print(text.decode())
print("Record Protocol Ends and Closing Sockets")
sock.shutdown(SHUT_RDWR)
sock.close()