# Unauthorized-Webpage-Access-Detection
Python software that monitors the network to determine if a network user has access a non-whitelisted webpage(or more accurately receives any unauthorized http traffic)

This is python software that utilized tShark(terminal-based package of Wireshark) to record network activity. The network data is filtered for http traffic and the IP's of any such traffic is recorded. A pre-determined whitelist was created with the domains of webpages that are permitted. The IP'sfor these domains are obtain dynamically and checked against the traffic and any mismatches would be a red flag as this means http traffic outside of these domains was received/sent. Program currently simply prints these unknown packets. Their domains can be obtained further using nslookup and further action taken if/where necessary.

Currently, traffic is only sniffed for a short period before it is recorded and cut-off, as the program is meant for example use. Code can easily be amended to allow for a endless loop of monitoring traffic, but this option is left up to the user of the program for the time being.

Requires: tshark nslookup matplotlib
