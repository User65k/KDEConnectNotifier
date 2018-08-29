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

DISCOVERY_PORT = 1714

PAIRING = 'kdeconnect.pair'
NOTIFICATION = 'kdeconnect.notification'
RUNCOMMAND = 'kdeconnect.runcommand'
ENCRYPTED = 'kdeconnect.encrypted'
IDENTITY = 'kdeconnect.identity'

KEY_FOLDER = './'
KEY_FILE_NAME = KEY_FOLDER+'private.pem'
KEY_PEER = KEY_FOLDER+'pub%s.pem'
