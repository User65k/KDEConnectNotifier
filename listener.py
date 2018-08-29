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
# User65k
#

import sys
import socket
import logging

from Crypto.Cipher import PKCS1_v1_5
from select import select

from KDEConnectNotifier.consts import DISCOVERY_PORT, RUNCOMMAND, NOTIFICATION
from KDEConnectNotifier.kde_con_proto import get_key, send_crypted, handle_packets, handle_identity, send_identity, netpkt


def handle_RUNCOMMAND(body, devID, sckt):
    if 'requestCommandList' in body:
        pkt = netpkt("kdeconnect.runcommand.request",
                    {'commandList': {
                        '123':{
                        'name': 'name',
                        'command': 'command'}
                    }})
        logging.debug('cmd list: %s', pkt)
        send_crypted(pkt, devID, sckt)
    elif 'key' in body:
        logging.debug('exec: #%s', body['key'])
        #echo -n "AUF" | nc -q 1 localhost 14000
        buz = socket.socket()
        buz.connect(('localhost', 14000))
        buz.send(b'AUF')
        buz.close()

def SendNotification(host, socket):
    #test notify
    pkt = netpkt(NOTIFICATION,
                {'id':'123',
                'ticker':'ticker',
                'appName':'appName',
                #'payload': //bitmap
                'isClearable':False,
                #'title':'title',
                #'text':'text',
                #'time':'123'
                })
    logging.debug('cmd list: %s', pkt)
    send_crypted(pkt, host, socket)

callbacks = {RUNCOMMAND: handle_RUNCOMMAND}

def main():
    key = get_key()
    cipher = PKCS1_v1_5.new(key)
    
    #connect to door
    bell = socket.socket()
    bell.connect(("127.0.0.1", 11000))

    # listen for packet on UDP socket
    discovery = socket.socket(type=socket.SOCK_DGRAM)
    discovery.bind(('0.0.0.0', DISCOVERY_PORT))

    #listen for new clients
    server = socket.socket()
    server.bind(('0.0.0.0', DISCOVERY_PORT))
    server.listen(5)

    wait_for = [bell, discovery, server]
    connections = {} # connection -> DeviceID
    pending_data = {} # DeviceID -> DataChunk

    while True:
        rl = select(wait_for,[],[])[0]
        for sckt in rl:
            if sckt==bell:
                #someone is at the door
                bell.recv(4096)
                #send notifications
                for s, h in connections.items():
                    SendNotification(h, s)

            elif sckt==discovery:
                #a new client is waiting for us to connect
                data, sender = discovery.recvfrom(1024)

                dev = handle_identity(data)

                if dev:
                    devID = dev['deviceId']
                    tcp_port = int(dev['tcpPort'])
                    logging.debug('Device %s is at tcp://%s:%d', devID, sender[0], tcp_port)

                    #init new connection
                    ts = socket.socket()
                    ts.connect((sender[0], tcp_port))
                    send_identity(ts)
                    #send_pair(ts, key.publickey().exportKey())

                    connections[ts] = devID
                    pending_data[devID] = ''
                    wait_for.append(ts)

            elif sckt==server:
                #a new client is connecting
                ts, client_address = server.accept()

                dev = handle_identity(ts.recv(4096))
                if dev:
                    devID = dev['deviceId']
                    #send_identity(connection)

                    connections[ts] = devID
                    pending_data[devID] = ''
                    wait_for.append(ts)
                else:
                    #not paired
                    ts.close()

            else:
                #get data from other stations
                devID = connections[sckt]
                pending_pkt = pending_data[devID] + sckt.recv(4096).decode('ascii')
                pos = pending_pkt.find('\n')
                if pos == -1:
                    logging.debug('expecting more data')
                else:
                    pkts = []
                    # logging.debug('pos %r', pos)
                    while len(pending_pkt) > 0 and pos != -1:
                        pkt = pending_pkt[0:pos]
                        logging.debug('got pkt: \'%s\'', pkt)
                        if len(pkt) > 0:
                            pkts.append(pkt)
                        pending_pkt = pending_pkt[pos + 1:]
                        # logging.debug('rest: \'%s\'', pending_pkt)
                        pos = pending_pkt.find('\n')
                        # logging.debug('pos %r', pos)

                    logging.debug('found %d complete packets', len(pkts))
                    handle_packets(pkts, cipher, devID, sckt, callbacks)
                
                #remember half pkgs
                pending_data[devID] = pending_pkt

if __name__ == '__main__':
    main()
