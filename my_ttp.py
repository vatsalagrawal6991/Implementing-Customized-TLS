from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
import socket
import sys
port = 1036
hostname = "127.0.0.1"
if (len(sys.argv)==2):
    port = int(sys.argv[1])
if (len(sys.argv)==3):
    portca = int(sys.argv[1])
    hostname = sys.argv[2]

#prkey = rsa.generate_private_key(65537,2048)
prkey = ec.generate_private_key(ec.SECP256R1())
pukey = prkey.public_key()
com = x509.NameAttribute(NameOID.COMMON_NAME, u"Agrawal")
TTP = x509.Name([com])
bui1 = x509.CertificateBuilder()
bui1 = bui1.issuer_name(TTP)
bui1 = bui1.serial_number(x509.random_serial_number())
bui1 = bui1.not_valid_after(datetime.utcnow() + timedelta(days = 20))
bui1 = bui1.not_valid_before(datetime.utcnow())
bui1 = bui1.subject_name(TTP)
bui1 = bui1.public_key(pukey)
bui1 = bui1.add_extension(x509.SubjectAlternativeName([x509.DNSName(u'localhost')]), critical=False)
cert21 = bui1.sign(prkey, hashes.SHA256())
certi1 = cert21.public_bytes(Encoding.PEM)
sock = socket.socket()
sock.bind((hostname,port))
sock.listen()
while 1:
    csock, chos= sock.accept()
    data = csock.recv(100000)
    csr = x509.load_pem_x509_csr(data)
    bui = x509.CertificateBuilder()
    bui = bui.issuer_name(TTP)
    bui = bui.serial_number(x509.random_serial_number())
    bui = bui.not_valid_after(datetime.utcnow() + timedelta(days = 20))
    bui = bui.not_valid_before(datetime.utcnow())
    bui = bui.subject_name(csr.subject)
    bui = bui.public_key(csr.public_key())
    bui = bui.add_extension(x509.SubjectAlternativeName([x509.DNSName(u'localhost')]), critical=False)
    cert2 = bui.sign(prkey, hashes.SHA256())
    cert = cert2.public_bytes(Encoding.PEM)
    csock.sendall(cert)
    #print(len(cert))
    #print(cert)
    #print(certi1)
    if csock.recv(10000) != b"ACK":
        csock.close()
        continue
    csock.sendall(certi1)
    print("All Certificate Send")
    csock.close()












