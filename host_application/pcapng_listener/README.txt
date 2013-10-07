
Compile on Mac/Linux:
 > make

Compile on Windows:
 > cl pcapng_listener.c ..\common\inet_pton.c ..\common\shared.c -I ..\..\module_pcapng\src -I ..\..\app_avb_tester\src -I ..\common


To connect to Wireshark using live mode over a pipe then do the following:
 > mkfifo pcap_pipe

In Wireshark go to:
 Capture -> Options

Then select "Manage Interfaces" and create a new pipe pointing at the "pcap_pipe" file created above.

Start recording on that interface and then run:
 > ./pcapng_listener -l pcap_pipe

