# KDEConnectNotifier
Send notifications to KDEConnect and receive commands.

I use it as a door bell notification with the [DoorBerryServer](https://github.com/User65k/DoorBerryServer)

All cedit for KDE Connect in Python to <https://github.com/bboozzoo/kdeconnect-python-mock>.

## Usage

First pair all peers you want to talk to:
```sh
python3 pair_cli.py
```

Then run in the background:
```sh
python3 listener.py &
```
Trigger the notification by sending something to TCP/11000 and initialize a connection to TCP/14000 by using the KDEConnect Command Plugin. You probably what to change that in `listener.py`.
