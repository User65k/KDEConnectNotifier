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

import logging

from select import select

from cryptography.hazmat.primitives import serialization

from KDEConnectNotifier.consts import PAIRING, KEY_PEER, DISCOVERY_PORT, DESKTOPS_PORT
from KDEConnectNotifier.kde_con_proto import handle_identity, send_identity, netpkt, ConnectionManager

def main():
    mgr = ConnectionManager()
    pkey = mgr.get_key().public_key().public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    discovery4, anounce, server = mgr.get_sockets()

    wait_for = [discovery4, server, anounce]

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
                        ts = mgr.prep_con_for(dev)

                        if ts.connect((sender[0], tcp_port)):
                            logging.info("connected "+ts.deviceName)
                            wait_for.append(ts) #ERROR:x2:No cert provided

                elif sckt==server:
                    #a new client is connecting
                    ts, client_address = server.accept()

                    con = mgr.accept(ts, get_unpaired=True)
                    if con is not None:
                        logging.info("accepted "+con.deviceName)
                        wait_for.append(con)
                    else:
                        #no valid msg
                        ts.close()

            for con in wait_for:
                if con in [discovery4, server, anounce]:
                    continue
                dev = con.dev_ident
                #ask user if its ok to pair
                cool = input("Pait with {deviceName} [y/N]: ".format(**dev))=="y"

                con.pair(cool)
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
