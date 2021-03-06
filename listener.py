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

from KDEConnectNotifier.consts import DISCOVERY_PORT, NOTIFICATION, DESKTOPS_PORT
from KDEConnectNotifier.kde_con_proto import get_key, send_crypted, handle_packets, handle_identity, send_identity, netpkt, runcmd

@runcmd
def command(devID):
    """name"""
    pass # write your code here

@runcmd
def command2(devID):
    """name 2"""
    pass # write your code here

def SendNotification(host, socket):
    #test notify
    pkt = netpkt(NOTIFICATION,
                {'id':'123',
                'ticker':'Tuer Klingel',
                'appName':'Tuer Klingel',
                #'payload': //bitmap
                'isClearable':False,
                #'title':'title',
                #'text':'text',
                #'time':'123'
                })
    logging.debug('notification: %s', pkt)
    send_crypted(pkt, host, socket)

def main():
    key = get_key()
    cipher = PKCS1_v1_5.new(key)
    
    #connect to door
    bell = socket.socket()
    bell.connect(("127.0.0.1", 11000))

    # listen for packet on UDP socket
    discovery = socket.socket(type=socket.SOCK_DGRAM)
    discovery.bind(('0.0.0.0', DISCOVERY_PORT))

    # listen for packet on UDP socket
    anounce = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    anounce.bind(('::', DESKTOPS_PORT))

    #listen for new clients
    server = socket.socket(socket.AF_INET6)
    server.bind(('::', DISCOVERY_PORT))
    server.listen(5)

    wait_for = [bell, discovery, server, anounce]
    connections = {} # connection -> DeviceID
    pending_data = {} # DeviceID -> DataChunk

    while True:
        rl = select(wait_for,[],[])[0]
        for sckt in rl:
            if sckt==bell:
                logging.info("bell")
                #someone is at the door
                bell.recv(10)
                #send notifications
                for s, h in connections.items():
                    try:
                        SendNotification(h, s)
                    except OSError:
                        #remove the dead
                        wait_for.remove(s)
                        try:
                            del connections[s]
                        except KeyError:
                            pass
                        try:
                            del pending_data[h]
                        except KeyError:
                            pass

            elif sckt==discovery or sckt==anounce:
                logging.debug("discovered a client")
                #a new client is waiting for us to connect
                data, sender = sckt.recvfrom(4096)

                dev = handle_identity(data)

                if dev:
                    devID = dev['deviceId']
                    tcp_port = int(dev['tcpPort'])
                    logging.debug('Device %s is at tcp://%s:%d', devID, sender[0], tcp_port)

                    #init new connection
                    ts = socket.socket()
                    try:
                        ts.connect((sender[0], tcp_port))
                    except OSError:
                        continue
                    send_identity(ts)
                    #send_pair(ts, key.publickey().exportKey())

                    connections[ts] = devID
                    pending_data[devID] = ''
                    wait_for.append(ts)

            elif sckt==server:
                logging.info("new client connecting")
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
                data = b""
                try:
                    data = sckt.recv(4096)
                except OSError:
                    pass
                
                #get data from other stations
                devID = connections[sckt]

                if not data:
                    #remove the dead
                    wait_for.remove(sckt)
                    try:
                        del connections[sckt]
                    except KeyError:
                        pass
                    try:
                        del pending_data[devID]
                    except KeyError:
                        pass
                    continue

                logging.debug("got peer data")
                pending_pkt = ""
                try:
                    pending_pkt = pending_data[devID]
                except KeyError:
                    pass
                pending_pkt += data.decode('ascii')
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
                    handle_packets(pkts, cipher, devID, sckt)
                
                #remember half pkgs
                pending_data[devID] = pending_pkt

if __name__ == '__main__':
    #logging.basicConfig(level=logging.INFO)
    main()
