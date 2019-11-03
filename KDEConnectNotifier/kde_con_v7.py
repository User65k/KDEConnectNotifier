
from ssl import SSLContext, CERT_NONE, CERT_REQUIRED, SSLError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from json import loads
from os import path

from KDEConnectNotifier.consts import KEY_FILE_NAME, PAIRING, KEY_PEER as CRT_PEER
from KDEConnectNotifier.kde_con_proto import KDEConnection, netpkt, OUR_KDE_DEVID

OWN_CERT_FILE = KEY_FILE_NAME + '_cert.pem'

class KDEConnectionProto7(KDEConnection):
    """TLS"""
    def __init__(self, own_key, dev_ident):
        super().__init__(dev_ident)
        self.ctx = SSLContext()
        #self.ctx.set_ciphers("TLSv1.3")

        if not path.exists(OWN_CERT_FILE):
            create_self_signed_cert(own_key, OWN_CERT_FILE, OUR_KDE_DEVID)
        self.ctx.load_cert_chain(OWN_CERT_FILE, KEY_FILE_NAME)
        if self.paired:
            self.ctx.load_verify_locations(cafile=CRT_PEER % (self.deviceId))  # PEM
            self.ctx.verify_mode = CERT_REQUIRED
        else:
            self.ctx.verify_mode = CERT_NONE

    def __check_peer_cert(self):
        if not self.paired:
            # device is not known, but we need an initial connection
            self.log.debug("No cert required. Unpaired")
            return True
        cert = self.socket.getpeercert(binary_form=True)
        if cert is None:
            self.log.debug("No cert")
            return False
        self.log.debug("Valid cert")
        return True
        #cert = x509.load_der_x509_certificate(cert, default_backend())
        #key = None
        #with open(CRT_PEER % (self.deviceId), 'rb') as inf:
        #    key = serialization.load_pem_public_key(inf.read(),
        #                                            backend=default_backend())
        #if cert.public_key() == key:
        #    return True
        #self.log.info("key missmatch")
        #self.log.debug(cert.public_key())
        #self.log.debug(key)
        #return False

    def connect(self, addr):
        if not super().connect(addr):
            return False
        try:
            #wait for client hello
            self.socket = self.ctx.wrap_socket(self.socket,
                                        server_side=True)
            if not self.__check_peer_cert():
                self.socket.close()
                return False
            return True
        except SSLError as e:
            self.log.exception(e.reason)
            return False
        except OSError as e:
            self.log.exception(e.args)
            return False

    def incomingsock(self, sock):
        try:
            #send client hello
            self.socket = self.ctx.wrap_socket(sock,
                                        server_side=False)
            if not self.__check_peer_cert():
                self.socket.close()
        except SSLError as e:
            self.log.exception(e.reason)
        except OSError as e:
            self.log.exception(e.args)

    def handle_packets(self, pkts, callbacks):
        """
        :param list pkts: list of packets
        :param dict callbacks: TYPE -> function(body, DeviceID, socket)
        """
        if not self.paired:
            self.log.info("not paired")
            return

        for pkt in pkts:
            try:
                p = loads(pkt)
                cmd = p['type']
                if cmd in callbacks:
                    callbacks[cmd](p['body'], self.deviceId, self.socket)

            except ValueError as e:
                self.log.exception(pkt, exc_info=e)
            except KeyError as e:
                self.log.exception(pkt, exc_info=e)

    def send_crypted(self, data):
        self.socket.send(data)

    def pair(self, accept_paring):
        if accept_paring:

            pkt = netpkt(PAIRING, {'pair': True })
            self.log.debug('own pair request: %s', pkt)
            self.socket.send(pkt)
            self.socket.send(b'\n')
            # -> recv key
            pkt = self.socket.recv(4096).decode('ascii')  # TODO no answer -> timeout
            pkt = pkt.splitlines()[0]
            p = {'type':'?'}
            try:
                p = loads(pkt)
            except ValueError:
                self.log.exception("odd data from device: "+pkt)
                return

            try:
                if p['type'] == PAIRING:
                    if p['body']['pair'] == False:
                        print("Device refused")
                        return
                    cert = self.socket.getpeercert(binary_form=True)
                    if cert is None:
                        self.log.error("No cert provided")
                        return
                    cert = x509.load_der_x509_certificate(cert, default_backend())
                    with open(CRT_PEER % (self.deviceId), 'wb') as ref:
                        ref.write(cert.public_bytes(serialization.Encoding.PEM))
                    print("Device added!")
            except KeyError as e:
                self.log.exception("Device {i.deviceName} sent: {d}".format(i=self, d=p))
        else:
            pkt = netpkt(PAIRING, {'pair': False})
            self.socket.send(pkt)
            self.socket.send(b'\n')

def create_self_signed_cert(priv_key, filename, devID):
    """
        CN (Vorname):	deviceId
        O (Organisation):	KDE
        OU (Organisationseinheit):	Kde connect

        Self-Signed
        Version:	3
        Schlüsselparameter:	05 00
    """
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from datetime import datetime, timedelta

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"KDE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Kde connect"),
        x509.NameAttribute(NameOID.COMMON_NAME, devID),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        priv_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=100)
    #).add_extension(
    #    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    #    critical=False,
    # Sign our certificate with our private key
    ).sign(priv_key, hashes.SHA256(), default_backend())

    # Version:	3
    # Schlüsselparameter:	05 00

    # Write our certificate out to disk.
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
