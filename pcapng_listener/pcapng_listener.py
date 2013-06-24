#!/usr/bin/env python

import socket
import time


TCP_IP = '127.0.0.1'
TCP_PORT = 12346
BUFFER_SIZE = 16384
MESSAGE = "Hello, World!"

prev_full = False

f = open('cap.pcap', 'w')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
for i in range(10):
    s.send(MESSAGE)
while 1:
    try:
        data = s.recv(BUFFER_SIZE)
        if (prev_full):
            start = 8
        else:
            start = 4

        if len(data) == 16332:
            prev_full = True
        else:
            prev_full = False


        for i in range(start, len(data)-1,16):
            xscope_val = data[i:i+4]
            f.write(xscope_val[::-1])
    except KeyboardInterrupt:
        f.close()
        s.close()
        sys.exit()
