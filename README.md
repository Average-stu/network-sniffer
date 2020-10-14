# Network-sniffer
A terminal sniffer made using c 

# Packet sniffer
Packet sniffers are programs that intercept the network traffic flowing in and out of a system through network interfaces.
So if you are browsing the internet then traffic is flowing and a packet sniffer would be able to catch it in the form of packets and display them for whatever reasons required.\
Packet sniffers are used for various needs like analysing protocols, monitoring network, and assessing the security of a network.\
Wireshark for example is the most popular packet sniffer out there and is available for all platforms. Its gui based and very easy to use.\
Packet sniffers can be coded by either using sockets api provided by the kernel, or by using some packet capture library like libpcap. 
# Basic Sniffer using sockets
To code a very simply sniffer in C the steps would be
1. Create a raw socket.
2. Put it in a recvfrom loop and receive data on it.\
A raw socket when put in recvfrom loop receives all incoming packets. This is because it is not bound to a particular address or port.

# Compile and Run
 >`gcc packet.c -o packet -lpcap` \
 >`sudo ./packet` 
 
 
 The program must be run as root user or superuser privileges. e.g. sudo ./packet in linux.\
 The program creates raw sockets which require root access.



