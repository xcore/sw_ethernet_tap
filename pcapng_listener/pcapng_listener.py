#!/usr/bin/env python

# Note that the device should be launched with:
#   xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
#

import socket
import struct
import sys
import time

TCP_IP = '127.0.0.1'
TCP_PORT = 12346
BUFFER_SIZE = 16384
CAPTURE_LENGTH = 64

# The xscope data comes as 4 words ([Type,ID,0,0], [data], [timestamp], [timestamp])
XSCOPE_PACKET_SIZE = 4 * 4

def emit_section_header_block(f):
  f.write(struct.pack('I', 0x0A0D0D0A))         # Block Type
  f.write(struct.pack('I', 32))                 # Block Total Length
  f.write(struct.pack('I', 0x1A2B3C4D))         # Byte-Order Magic
  f.write(struct.pack('h', 0x1))                # Major Version
  f.write(struct.pack('h', 0x0))                # Minor Version
  f.write(struct.pack('I', 0xffffffff))         # Section Length
  f.write(struct.pack('I', 0xffffffff))         # Section Length
  f.write(struct.pack('I', 0x0))                # Options
  f.write(struct.pack('I', 32))                 # Block Total Length

def emit_interface_description_block(f):
  f.write(struct.pack('I', 0x1))                # Block Type
  f.write(struct.pack('I', 24))                 # Block Total Length
  f.write(struct.pack('h', 0x1))                # LinkType
  f.write(struct.pack('h', 0x0))                # Reserved
  f.write(struct.pack('I', CAPTURE_LENGTH))     # SnapLen
  f.write(struct.pack('I', 0x0))                # Options
  f.write(struct.pack('I', 24))                 # Block Total Length

if __name__ == "__main__":
    prev_full = False

    f = open('cap.pcapng', 'wb')
    emit_section_header_block(f)

    # Emit two interface descriptions as there are two on the tap
    emit_interface_description_block(f)
    emit_interface_description_block(f)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    
    # Tell the server that we want to receive data (send hex value 2)
    s.send(struct.pack('b', 2))
    total_received = 0
    while 1:
        try:
            data = s.recv(BUFFER_SIZE)
            total_received += len(data) / XSCOPE_PACKET_SIZE
            sys.stdout.write("\r%d" % total_received)
            # There is only one byte at a time sent in each message

#            print "Received %s" % " ".join(["%d" % struct.unpack('b', b)[1] for b in bytes(data)])
            for i in range(0, len(data), XSCOPE_PACKET_SIZE):
                f.write(data[i+4]) 
#                print "Writing %s" % struct.unpack('b', data[i+4])[0]

    
        except KeyboardInterrupt:
            print "Finishing"
            f.close()
            s.close()
            sys.exit()
