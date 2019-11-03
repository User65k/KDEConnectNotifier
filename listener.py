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

import socket
import logging

from KDEConnectNotifier.consts import KEY_FILE_NAME, KEY_PEER
from Crypto.Cipher import PKCS1_v1_5
from select import select

from KDEConnectNotifier.consts import DISCOVERY_PORT, NOTIFICATION, DESKTOPS_PORT
from KDEConnectNotifier.kde_con_proto import netpkt, runcmd, handle_identity, ConnectionManager, KDEConnection

@runcmd
def command(devID):
    """name"""
    pass # write your code here

@runcmd
def command2(devID):
    """name 2"""
    pass # write your code here

def SendNotification(socket):
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
    socket.send_crypted(pkt)

def main():
    mgr = ConnectionManager()
    
    #connect to door
    bell = socket.socket()
    bell.connect(("127.0.0.1", 11000))

    discovery, anounce, server = mgr.get_sockets()

    wait_for = [bell, discovery, server, anounce]

    while True:
        rl = select(wait_for,[],[])[0]
        for sckt in rl:
            if sckt==bell:
                logging.info("bell")
                #someone is at the door
                bell.recv(10)
                #send notifications
                for s in wait_for:
                    if not isinstance(s, KDEConnection):
                        continue
                    try:
                        SendNotification(s)
                    except OSError:
                        #remove the dead
                        wait_for.remove(s)

            elif sckt==discovery or sckt==anounce:
                logging.debug("discovered a client")
                #a new client is waiting for us to connect
                data, sender = sckt.recvfrom(4096)

                dev = handle_identity(data)

                if dev:
                    deviceName = dev['deviceName']
                    tcp_port = int(dev['tcpPort'])
                    logging.info('Device %s is at tcp://%s:%d', deviceName, sender[0], tcp_port)

                    #init new connection
                    ts = mgr.prep_con_for(dev)

                    if ts.connect((sender[0], tcp_port)):
                        wait_for.append(ts)

            elif sckt==server:
                logging.info("new client connecting")
                #a new client is connecting
                ts, client_address = server.accept()
                con = mgr.accept(ts)
                if con is not None:
                    wait_for.append(con)
                else:
                    #not paired
                    ts.close()

            else:
                sckt.recv_and_handle()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
