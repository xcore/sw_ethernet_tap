
Compile on Mac/Linux:
 > make

Compile on Windows:
 > xmake

Note that on Windows you will need the XMOS tools and Visual Studio on the path for this to work.


To connect to Wireshark using live mode over a pipe then do the following:
 > mkfifo pcap_pipe

In Wireshark go to:
 Capture -> Options

Then select "Manage Interfaces" and create a new pipe pointing at the "pcap_pipe" file created above.

Start recording on that interface and then run:
 > ./pcapng_listener -l pcap_pipe

