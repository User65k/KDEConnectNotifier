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

import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from KDEConnectNotifier.consts import DESKTOPS_PORT, DISCOVERY_PORT, PAIRING, NOTIFICATION, RUNCOMMAND, IDENTITY, KEY_FILE_NAME, KEY_PEER


OUR_KDE_DEVID = None


def getKdeDevId():
    """return an identifier for this host.
    On android ANDROID_ID (64bit number as 16byte hexstr) is used.

    We use the MAC as (12byte) hexstr
    """
    global OUR_KDE_DEVID
    if OUR_KDE_DEVID:
        return OUR_KDE_DEVID

    from uuid import getnode
    OUR_KDE_DEVID = getnode().to_bytes(6, byteorder="big").hex()

    return OUR_KDE_DEVID

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
        'deviceId': getKdeDevId(),
        'deviceName': socket.gethostname(),
        'deviceType': 'desktop',
        #'protocolVersion': 5,
        #'SupportedIncomingInterfaces': [RUNCOMMAND],
        #'SupportedOutgoingInterfaces': [NOTIFICATION, RUNCOMMAND]
        'protocolVersion': 7,
        'incomingCapabilities': [RUNCOMMAND],
        'outgoingCapabilities': [NOTIFICATION, RUNCOMMAND]
    }
    if ts.type == socket.SOCK_DGRAM:
        pl['tcpPort'] = str(DISCOVERY_PORT)

    pkt = netpkt(IDENTITY,pl)
    logging.debug('own identity: %s', pkt)
    if ts.type == socket.SOCK_DGRAM:
        ts.sendto(pkt+b'\n',('<broadcast>',DESKTOPS_PORT))
    else:
        ts.sendall(pkt)
        ts.sendall(b'\n')


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

                if devID == getKdeDevId():
                    #always ignore yourself
                    return None
                
                already_paired = path.exists(KEY_PEER % (devID))
                if get_unpaired or already_paired:
                    pkt['body']['paired'] = already_paired
                    return pkt['body']

        except ValueError:
            print(data)
        except KeyError:
            print(data)

        return None

def mem_find(memview, search):
    needle = ord(search)
    i = 0
    l = len(memview)
    while i < l:
        if memview[i] == needle:
            return i
        i += 1
    return -1

class ConnectionManager():
    def __init__(self):
        self.priv_key = self.get_key()

    def get_key(self):
        """
        Load private key from file or generate a new one
        :return: RSA key object
        :rtype: RSA
        """
        private_key = None
        if path.exists(KEY_FILE_NAME):
            with open(KEY_FILE_NAME, 'rb') as inf:
                private_key = serialization.load_pem_private_key(
                    inf.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            with open(KEY_FILE_NAME, 'wb') as outf:
                outf.write(private_key.private_bytes(
                   encoding=serialization.Encoding.PEM,
                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                   encryption_algorithm=serialization.NoEncryption()
                ))
        return private_key

    def prep_con_for(self, dev_json):
        logging.debug("prep_con_for:")
        logging.debug(dev_json)
        if dev_json['protocolVersion'] == 5:
            from KDEConnectNotifier.kde_con_v5 import KDEConnectionProto5
            return KDEConnectionProto5(self.priv_key, dev_json)
        elif dev_json['protocolVersion'] == 7:
            from KDEConnectNotifier.kde_con_v7 import KDEConnectionProto7
            return KDEConnectionProto7(self.priv_key, dev_json)
        else:
            raise ValueError("Protocol Version not supported")

    def get_sockets(self):
        # listen for packet on UDP socket
        discovery = socket.socket(type=socket.SOCK_DGRAM)
        discovery.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery.bind(('0.0.0.0', DISCOVERY_PORT))
        discovery.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # listen for packet on UDP socket
        anounce = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        anounce.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        anounce.bind(('::', DESKTOPS_PORT))

        #listen for new clients
        server = socket.socket(socket.AF_INET6)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('::', DISCOVERY_PORT))
        server.listen(5)
        return (discovery, anounce, server)

    def accept(self, new_con, get_unpaired=False):
        dev = handle_identity(new_con.recv(4096), get_unpaired)
        if dev is None:
            return None
        con = self.prep_con_for(dev)
        if con is None:
            return None
        con.incomingsock(new_con)
        return con

class KDEConnection():
    """
    connection to a single device
    """
    
    def __init__(self, dev_ident):
        self.dev_ident = dev_ident
        self.socket = None
        self.log = logging.getLogger(dev_ident["deviceName"])

    def close(self):
        if self.socket is not None:
            self.socket.close()

    def __getattr__(self, attr):
        return self.dev_ident[attr]

    def fileno(self):
        """for select"""
        return self.socket.fileno()

    def connect(self, addr):
        self.socket = socket.socket()
        try:
            self.socket.connect(addr)
        except OSError:
            return False
        send_identity(self.socket)
        return True
    
    def incomingsock(self, sock):
        self.socket = sock

    def handle_packets(self, pkts, callbacks):
        raise NotImplementedError()

    def recv_and_handle(self, **kwargs):
        if "callbacks" not in kwargs:
            kwargs["callbacks"] = default_callbacks
        data = b""
        try:
            data = self.socket.recv(4096)
        except OSError:
            pass
        
        if not data:
            #remove the dead
            self.socket.close()
            return False

        self.log.debug("got peer data")
        pending_pkt = self.pending_data
        pending_pkt += data
        pending_pkt = memoryview(pending_pkt)
        pos = mem_find(pending_pkt, '\n')
        if pos == -1:
            self.log.debug('expecting more data')
        else:
            pkts = []
            # self.log.debug('pos %r', pos)
            while len(pending_pkt) > 0 and pos != -1:
                pkt = pending_pkt[0:pos]
                if len(pkt) > 0:
                    pkts.append(bytes(pkt))
                    self.log.debug('got pkt: \'%s\'', pkts[-1])
                pending_pkt = pending_pkt[pos + 1:]
                # self.log.debug('rest: \'%s\'', pending_pkt)
                pos = mem_find(pending_pkt, '\n')
                # self.log.debug('pos %r', pos)

            self.log.debug('found %d complete packets', len(pkts))
            self.handle_packets(pkts, **kwargs)
        
        #remember half pkgs
        self.pending_data = pending_pkt
        return True

    def send_crypted(self, data):
        raise NotImplementedError()

    def pair(self, accept_paring):
        raise NotImplementedError()
