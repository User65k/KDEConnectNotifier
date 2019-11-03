from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from json import loads
from base64 import b64decode, b64encode

from KDEConnectNotifier.consts import PAIRING, ENCRYPTED, KEY_PEER
from KDEConnectNotifier.kde_con_proto import KDEConnection, netpkt


class KDEConnectionProto5(KDEConnection):
    """asym crypto over json"""
    def __init__(self, own_key, dev_ident):
        super().__init__(dev_ident)
        self.own_key = own_key
        self.pending_data = b''

    def connect(self, addr):
        if not super().connect(addr):
            return False
        self.pending_data = b''
        return True

    def handle_packets(self, pkts, callbacks):
        """
        :param list pkts: list of packets
        :param dict callbacks: TYPE -> function(body, DeviceID, socket)
        """
        if not self.paired:
            self.log.info(self.deviceId+" not paired")
            return

        for pkt in pkts:
            try:
                p = loads(pkt)
                if p['type'] == ENCRYPTED:
                    self.log.debug('encrypted packet')

                    data = ''
                    for data_chunk in p['body']['data']:
                        self.log.debug('encrypted data: %s', data_chunk)
                        dec = self.own_key.decrypt(b64decode(data_chunk), padding.PKCS1v15())
                        if not dec:
                            self.log.error('failed to decrypt packet data, perhaps need to pair again?')
                        else:
                            self.log.debug('decrypted: %r', dec)
                            try:
                                data += dec.decode('utf-8')
                            except UnicodeDecodeError as e:
                                self.log.exception(dec, exc_info=e)

                    if data:
                        self.log.debug('decrypted data: %r', data)
                        p = loads(data)
                        cmd = p['type']
                        if cmd in callbacks:
                            callbacks[cmd](p['body'], self.deviceId, self.socket)
                        
                    else:
                        self.log.debug('no data available')
                elif p['type'] == PAIRING:
                    with open(KEY_PEER % (self.deviceId), 'r') as ref:
                        old = ref.read()
                        new = p['body']['publicKey']
                        if old == new:
                            #same Key, good
                            pass
                        else:
                            #bad
                            self.log.warning('wrong key\n--\n%s\n---\n%s\n---', old, new)
                            self.socket.close()
                else:
                    self.log.info('other type: %s', p['type'])

            except ValueError as e:
                self.log.exception(pkt, exc_info=e)
            except UnicodeDecodeError as e:
                self.log.exception(pkt, exc_info=e)
            except KeyError as e:
                self.log.exception(pkt, exc_info=e)

    def send_crypted(self, data):
        """
        Send encrypted packet to peer
        """
        key = None
        with open(KEY_PEER % (self.deviceId), 'rb') as inf:
            key = serialization.load_pem_public_key(inf.read(),
                                                    backend=default_backend())

        #longer than the RSA modulus (in bytes) minus 11
        chunks, chunk_size = len(clear), 245
        parts = [ clear[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
        enc = []
        for plain in parts:
            enc.append( b64encode(key.encrypt(plain, padding.PKCS1v15()),
                                  None).decode('ascii') )

        pkt = netpkt(ENCRYPTED,
                    {'data':enc
                    })
        self.socket.send(pkt)
        self.socket.send(b'\n')

    def pair(self, accept_paring):
        if accept_paring:

            pkt = netpkt(PAIRING,
                        {'pair': True,
                         'publicKey': self.own_key.publickey().exportKey().decode('ascii')})
            self.log.debug('pair request: %s', pkt)
            self.socket.send(pkt)
            self.socket.send(b'\n')
            # -> recv key
            pkt = self.socket.recv(4096).decode('ascii').splitlines()[0]  # TODO no answer -> timeout
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
                    with open(KEY_PEER % (self.deviceId), 'w') as ref:
                        ref.write(p['body']['publicKey'])
                    print("Device added!")
            except KeyError as e:
                self.log.exception("Device {i.deviceName} sent: {d}".format(i=self, d=p))
        else:
            pkt = netpkt(PAIRING, {'pair': False})
            self.socket.send(pkt)
            self.socket.send(b'\n')
