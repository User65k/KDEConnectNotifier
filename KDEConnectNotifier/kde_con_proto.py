#!/usr/bin/python3

import logging
from json import loads, dumps
from time import time
from os import path
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from KDEConnectNotifier.consts import PAIRING, NOTIFICATION, RUNCOMMAND, ENCRYPTED, IDENTITY, KEY_FILE_NAME, KEY_PEER


def netpkt(tp, data):
    d = {
        'id': int(time() * 1000),
        'type': tp,
        'body': data
    }
    return dumps(d).encode('ascii')

def send_identity(ts):
    """
    :ts: socket
    """
    pkt = netpkt(IDENTITY,
                {
                    'deviceId': '123',
                    'deviceName': 'Door',
                    'deviceType': 'desktop',
                    'protocolVersion': 5,
                    'SupportedIncomingInterfaces': [RUNCOMMAND],
                    'SupportedOutgoingInterfaces': [NOTIFICATION, RUNCOMMAND]
                })
    logging.debug('identity: %s', pkt)
    ts.send(pkt)
    ts.send(b'\n')

def send_pair(ts, key):
    """
    :param socket.socket ts: socket
    :param: PEM encoded public key
    """
    # logging.debug('public key: %s', key)

    pkt = netpkt(PAIRING,
                 {'pair': True, 'publicKey': key.decode('ascii')})
    logging.debug('pair request: %s', pkt)
    ts.send(pkt)
    ts.send(b'\n')

def handle_packets(pkts, cipher, host, socket, callbacks):
    """
    :param list pkts: list of packets
    """
    for pkt in pkts:
        try:
            p = loads(pkt)
            if p['type'] == ENCRYPTED:
                logging.debug('encrypted packet')

                data = ''
                for data_chunk in p['body']['data']:
                    logging.debug('encrypted data: %s', data_chunk)
                    dec = cipher.decrypt(b64decode(data_chunk), None)
                    # dec = cipher.decrypt(data_chunk, None)
                    if not dec:
                        logging.error('failed to decrypt packet data, perhaps need to pair again?')
                    else:
                        logging.debug('decrypted: %r', dec)
                        try:
                            data += dec.decode('utf-8')
                        except UnicodeDecodeError as e:
                            logging.exception(dec, exc_info=e)

                if data:
                    logging.debug('decrypted data: %r', data)
                    p = loads(data)
                    cmd = p['type']
                    if cmd in callbacks:
                        callbacks[cmd](p['body'], host, socket)
                    
                else:
                    logging.debug('no data available')
            elif p['type'] == PAIRING:
                with open(KEY_PEER % (host), 'r') as ref:
                    old = ref.read()
                    new = p['body']['publicKey']
                    if old == new:
                        #same Key, good
                        pass
                    else:
                        #bad
                        logging.warning('wrong key\n--\n%s\n---\n%s\n---', old, new)
                        socket.close()
            else:
                logging.info('other type: %s', p['type'])

        except ValueError as e:
            logging.exception(pkt, exc_info=e)

def send_crypted(clear, host, socket):
    key = None
    with open(KEY_PEER % (host), 'rb') as inf:
        key = RSA.importKey(inf.read())
    cipher = PKCS1_v1_5.new(key)
    enc = b64encode(cipher.encrypt(clear), None)

    pkt = netpkt(ENCRYPTED,
                {'data':[enc.decode('ascii')]
                })
    socket.send(pkt)
    socket.send(b'\n')

def get_key():
    """
    Load private key from file or generate a new one
    :return: RSA key object
    :rtype: RSA
    """
    if path.exists(KEY_FILE_NAME):
        with open(KEY_FILE_NAME, 'rb') as inf:
            key = RSA.importKey(inf.read())
    else:
        key = RSA.generate(2048)
        with open(KEY_FILE_NAME, 'wb') as outf:
            outf.write(key.exportKey('PEM'))
    return key

def handle_identity(data):
    pkt = loads(data.decode('ascii'))
    logging.debug('discovered: %r', pkt)
    if pkt['type'] == IDENTITY:
        devID = pkt['body']['deviceId']
        tcp_port = None
        if 'tcpPort' in pkt['body']:
            tcp_port = pkt['body']['tcpPort']

        if path.exists(KEY_PEER % (devID)):
            return devID, tcp_port

    return None, None
