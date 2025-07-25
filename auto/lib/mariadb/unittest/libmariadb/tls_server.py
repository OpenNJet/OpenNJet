import socket
import ssl
import argparse
from ast import literal_eval
from OpenSSL import crypto, SSL
import os

class TlsServer():

    def __init__(self, *args, **kwargs):
        self.host= kwargs.pop("host", "127.0.0.1")
        self.port= kwargs.pop("port", 50000)
        self.server= None
        self.end= False

        try:
            self.server= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.host, self.port))
            print("# tls dummy_server started: ", self.host, self.port)
            self.server.listen()
        except Exception as e:
            print("Couldn't start tls_server")
            print(e)

    def check_server(self):
        if not self.server:
            raise Exception("Server not started")
             

    def send_server_hello(self, conn):
        self.check_server()
        try:
            conn.sendall(server_hello)
        except Exception as e:
            print("Couldn't send server_hello")
            print(e)
            return 0
        return 1

    def generate_cert(self,
                      create_new=False,
                      create_crl=False,
                      emailAddress="emailAddress",
                      commonName="commonName",
                      SAN=None,
                      countryName="NT",
                      localityName="localityName",
                      stateOrProvinceName="stateOrProvinceName",
                      organizationName="organizationName",
                      organizationUnitName="organizationUnitName",
                      serialNumber=123,
                      validityStartInSeconds=0,
                      validityEndInSeconds=10*365*24*60*60,
                      KEY_FILE = "privkey.pem",
                      CRL_FILE = "selfsigned.crl",
                      CERT_FILE="selfsigned.pem"):


        self.key_file= KEY_FILE
        self.cert_file= CERT_FILE
        self.crl_file = CRL_FILE

        if create_new:
            try:
                k = crypto.PKey()
                k.generate_key(crypto.TYPE_RSA, 4096)
                # create a self-signed cert
                cert = crypto.X509()
                cert.get_subject().C = countryName
                cert.get_subject().ST = stateOrProvinceName
                cert.get_subject().L = localityName
                cert.get_subject().O = organizationName
                cert.get_subject().OU = organizationUnitName
                cert.get_subject().CN = commonName
                cert.get_subject().emailAddress = emailAddress
                cert.set_serial_number(serialNumber)
                cert.gmtime_adj_notBefore(validityStartInSeconds)
                cert.gmtime_adj_notAfter(validityEndInSeconds)
                cert.set_issuer(cert.get_subject())
                if SAN:
                   print(SAN)
                   san_list= [SAN,]
                   cert.add_extensions([
                      crypto.X509Extension(
                      b"subjectAltName", False, "," . join(san_list).encode()
                   )])
                cert.set_pubkey(k)
                cert.sign(k, 'sha512')
                with open(CERT_FILE, "wt") as f:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
                with open(KEY_FILE, "wt") as f:
                    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
                return 1
            except Exception as e:
                return 0
        return 1


    def set_tls_context(self, reply):
        kwargs= {}
        if len(reply) > 0:
            cmds= reply.decode()
            kwargs= dict((k, literal_eval(v)) for k, v in (pair.split('=') for pair in cmds.split()))
        print("# command: ", kwargs)
        if self.generate_cert(**kwargs):
            print("# loading certs", self.cert_file, self.key_file)
            self.context= ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(self.cert_file, self.key_file)
            return 1
        return 0
            

    def accept(self):
        self.check_server()
        conn, addr= self.server.accept()
        return (conn, addr)

    def run(self):
        while not self.end:
            connection, address= self.accept()
            print("# new connection")
            self.send_server_hello(connection)
            reply= connection.recv(4096)
            if reply[:4] == b'CMD:':
                if self.set_tls_context(reply[4:]):
                    connection.sendall(b'OK')
            elif reply[:4] == b'QUIT':
                print("# exiting tls_dummy_server")
                try:
                    connection.close()
                except:
                    pass
                return
            else:
                try:
                    tls_sock= self.context.wrap_socket(connection, server_side=True)
                except Exception as e:
                    print("error occured")
                    print(e)
                    connection.close()
            connection.close()

# Hardcoded server hello packet (captured from MariaDB Server 11.4.2)
server_hello = b'R\x00\x00\x00\n11.4.2-MariaDB\x00\xff\x01\x00\x00Nv\
*hQ;qK\x00\xfe\xff\x08\x02\x00\xff\x81\x15\x00\x00\x00\
\x00\x00\x00\x1d\x00\x00\x00`$-VIJyC!x[?\x00mysql_native_password\x00'


if __name__ == '__main__':

    parser= argparse.ArgumentParser(
                       prog='tls_server',
                       description='Simple TLS dummy test server')
    parser.add_argument('--host', help='Hostaddress of TLS test server (Default 127.0.0.1)')
    parser.add_argument('--port', help='Port of TLS test server. (Default 50000)')

    args= parser.parse_args()

    if not (port := args.port):
        port= 50000;
    if not (host := args.host):
        host= "127.0.0.1"
    server= TlsServer(host=host, port=int(port))
    print("# Starting tls_dummy_server")
    server.run()
