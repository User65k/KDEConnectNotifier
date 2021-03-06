#!/usr/bin/python3
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# AUTHORS
# Maciek Borzecki <maciek.borzecki (at] gmail.com> https://github.com/bboozzoo/kdeconnect-python-mock
# User65k
#

import logging
from json import loads, dumps
from time import time
from os import path
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from socket import SOCK_DGRAM

from KDEConnectNotifier.consts import DESKTOPS_PORT, DISCOVERY_PORT, PAIRING, NOTIFICATION, RUNCOMMAND, ENCRYPTED, IDENTITY, KEY_FILE_NAME, KEY_PEER

OUR_KDE_DEVID = '123'

desc_list = {}
func_list = {}
def handle_RUNCOMMAND(body, devID, sckt):
    global func_list, desc_list
    if 'requestCommandList' in body:
        pkt = netpkt("kdeconnect.runcommand.request", {'commandList': desc_list})
        logging.debug('cmd list: %s', pkt)
        send_crypted(pkt, devID, sckt)
    elif 'key' in body:
        fid = body['key']
        logging.info('exec: #%s', fid)
        if fid in func_list:
            try:
                func_list[fid](devID)
            except Exception:
                logging.exception("can't exec function")

def runcmd(func):
    global func_list, desc_list
    from time import time
    new_id = str(time())
    desc_list[new_id] = {'name': func.__doc__,'command': func.__name__}
    func_list[new_id] = func

default_callbacks = {RUNCOMMAND: handle_RUNCOMMAND}

def netpkt(tp, data):
    """
    Construct a new packet

    :tp: type of data packet
    :data: body of data packet
    """
    d = {
        'id': int(time() * 1000),
        'type': tp,
        'body': data
    }
    return dumps(d).encode('ascii')

def send_identity(ts):
    """
    :param socket.socket ts: socket to send on
    """
    pl = {
        'deviceId': OUR_KDE_DEVID,
        'deviceName': 'Door',
        'deviceType': 'desktop',
        'protocolVersion': 5,
        'SupportedIncomingInterfaces': [RUNCOMMAND],
        'SupportedOutgoingInterfaces': [NOTIFICATION, RUNCOMMAND]
    }
    if ts.type == SOCK_DGRAM:
        pl['tcpPort'] = str(DISCOVERY_PORT)

    pkt = netpkt(IDENTITY,pl)
    logging.debug('identity: %s', pkt)
    if ts.type == SOCK_DGRAM:
        ts.sendto(pkt+b'\n',('<broadcast>',DESKTOPS_PORT))
    else:
        ts.send(pkt)
        ts.send(b'\n')

def send_pair(ts, key):
    """
    :param socket.socket ts: socket to send on
    :param: PEM encoded public key
    """
    # logging.debug('public key: %s', key)

    pkt = netpkt(PAIRING,
                 {'pair': True, 'publicKey': key.decode('ascii')})
    logging.debug('pair request: %s', pkt)
    ts.send(pkt)
    ts.send(b'\n')

def handle_packets(pkts, cipher, host, socket, callbacks = default_callbacks):
    """
    :param list pkts: list of packets
    :param Crypto.Cipher.PKCS1_v1_5 cipher: decryption class
    :param str host: DeviceID of the peer we talk to
    :param socket.socket socket: socket
    :param dict callbacks: TYPE -> function(body, host, socket)
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
    """
    Send encrypted packet to peer
    :param str host: DeviceID of the peer we talk to
    :param socket.socket socket: socket
    """
    key = None
    with open(KEY_PEER % (host), 'rb') as inf:
        key = RSA.importKey(inf.read())
    cipher = PKCS1_v1_5.new(key)

    #longer than the RSA modulus (in bytes) minus 11
    chunks, chunk_size = len(clear), 245
    parts = [ clear[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
    enc = []
    for plain in parts:
        enc.append( b64encode(cipher.encrypt(plain), None).decode('ascii') )

    pkt = netpkt(ENCRYPTED,
                {'data':enc
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

def handle_identity(data, get_unpaired=False):
    """
    Check if data steam is connected to a device

    :param bytes data: bytes containing identity packet of peer
    :param bool get_unpaired: also return unpaired devices. Delaut no
    :return: IDENTITY description. keys: deviceId, deviceName, deviceType, tcpPort (opt)
    :rtype: dict
    """
    try:
        pkt = loads(data.decode('ascii').strip())
        logging.debug('discovered: %r', pkt)
        if pkt['type'] == IDENTITY:
            devID = pkt['body']['deviceId']

            if devID==OUR_KDE_DEVID:
                #always ignore yourself
                return None
            
            if get_unpaired or path.exists(KEY_PEER % (devID)):
                return pkt['body']

    except ValueError:
        print(data)
    except KeyError:
        print(data)

    return None
