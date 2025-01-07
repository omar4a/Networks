To run the DHCP server, please do the following:

- Make sure you have npcap installed.

- Make sure your device is connected to the internet.
(You can release/renew later to test the server. But as the server first starts, you must be connected to the internet so the server
can get network info)

- Make sure you are connected via an ethernet cable.
(The server works on any interface, but it's most reliable on ethernet)

- Turn off the default DHCP server from your router admin page. This is to make sure it doesn't intercept or interrupt this server.

- Get your two preferred DNS servers. Probably one of them is 192.168.1.1, the DNS server in your Router. And the other is the
default server of your ISP.
Vodafone: 62.240.110.217
WE: 163.121.128.134
Etisalat: 197.199.253.253
Orange: 213.131.65.20

- Go the "dist" directory inside the "Proj" directory, and run DHCP.exe

- Enter the values for lease time, renewal time, rebinding time, DNS servers, and domain name as prompted.

- The DHCP server is now running.