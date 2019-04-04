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

# send broadcast
# -> get connected
# -> recv ident
# -> recv key
# -> send key ?
# listen to broadcast
# -> connect
# -> send ident
# -> sent key
# -> recv key

import sys
import socket
import logging

from Crypto.Cipher import PKCS1_v1_5
from select import select
from json import loads

from KDEConnectNotifier.consts import PAIRING, KEY_PEER, DISCOVERY_PORT, DESKTOPS_PORT
from KDEConnectNotifier.kde_con_proto import get_key, handle_identity, send_identity, send_pair, netpkt

def main():
    pkey = get_key().publickey().exportKey()
    
    # listen for packet on UDP socket
    discovery4 = socket.socket(type=socket.SOCK_DGRAM)
    discovery4.bind(('0.0.0.0', DISCOVERY_PORT))
    discovery4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # listen for packet on UDP socket
    anounce = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    anounce.bind(('::', DESKTOPS_PORT))

    #listen for new clients
    server = socket.socket(socket.AF_INET6)
    server.bind(('::', DISCOVERY_PORT))
    server.listen(15)

    wait_for = [discovery4, server, anounce]
    connections = {}

    send_identity(discovery4)

    try:
        print("Discovering... Strg+C to quit")
        while True:

            rl = select(wait_for,[],[], 1)[0]
            for sckt in rl:
                # send broadcast
                # -> get connected
                # -> recv ident
                # listen to broadcast
                # -> connect
                # -> send ident
                if sckt==discovery4 or sckt==anounce:
                    #a new client is waiting for us to connect
                    data, sender = sckt.recvfrom(4096)

                    dev = handle_identity(data, get_unpaired=True)

                    if dev:
                        tcp_port = int(dev['tcpPort'])
                        logging.info('Device %s is at tcp://%s:%d', dev['deviceName'], sender[0], tcp_port)

                        #init new connection
                        ts = socket.socket()
                        ts.connect((sender[0], tcp_port))
                        send_identity(ts)

                        connections[ts] = dev
                        wait_for.append(ts)

                elif sckt==server:
                    #a new client is connecting
                    ts, client_address = server.accept()

                    dev = handle_identity(ts.recv(4096), get_unpaired=True)
                    if dev:
                        connections[ts] = dev
                        wait_for.append(ts)
                    else:
                        #no valid msg
                        ts.close()

            for con in wait_for:
                if con in [discovery4, server, anounce]:
                    continue
                dev = connections[con]
                #ask user if its ok to pair
                cool = input("Pait with {deviceName} [y/N]: ".format(**dev))=="y"

                if cool:
                    send_pair(con, pkey)
                    # -> recv key
                    pkt = con.recv(4096).decode('ascii').strip() #TODO no answer -> timeout
                    p = {'type':'?'}
                    try:
                        p = loads(pkt)
                    except ValueError:
                        logging.exception("odd data from device: "+pkt)

                    logging.info("Device {i[deviceName]} sent: {d}".format(i=dev, d=p))
                    if p['type'] == PAIRING:
                        with open(KEY_PEER % (dev['deviceId']), 'w') as ref:
                            ref.write(p['body']['publicKey'])
                        print("Device added!")
                else:

                    pkt = netpkt(PAIRING, {'pair': False})
                    con.send(pkt)
                    con.send(b'\n')
                wait_for.remove(con)
                con.close()

    except KeyboardInterrupt:
        print()
        
    except Exception as e:
        logging.exception("main", exc_info=e)
    
    for con in wait_for:
        con.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
