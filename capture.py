import pyshark
import matplotlib.pyplot as plt
from nslookup import Nslookup

whitelist=["google.com","wikipedia.com"]
ipWhitelist=[]

def captureData(dataFilter="",timeout=15):
    capture = pyshark.LiveCapture(
        interface='ethmon0',
        display_filter=dataFilter) #replace with your interface(use listInterfaces() to view all available)
    capture.set_display_filter('http')
    if (timeout!=0):
        capture.sniff(timeout=timeout)
    packets = [pkt for pkt in capture._packets]
    capture.close()
    return packets

def getWhiteListIPs():
    dnsCheck=Nslookup()
    for domain in whitelist:
        ip=dnsCheck.dns_lookup(domain)
        ipWhitelist.append(ip.answer)

def listInterfaces():
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    print("Available Interfaces:")
    for interface in interfaces:
        print(f"- {interface}")

def printAllPackets(capture):
    print("Capture Data:")
    for pkt in capture:
        print(pkt)

def printUnknownPackets(capture):
    for packet in capture:
        try:
            if packet.ip.src not in ipWhitelist and packet.ip.dst not in ipWhitelist:
                print(packet)
        except AttributeError:
            # Packets that do not have IP layer
            continue

def prettyPrintProtocolsChart(capture):
    layers={}
    for pkt in capture:
        for layer in pkt.layers:
            if (layer in layers):
                layers[layer.layer_name]+=1
            else:
                layers[layer.layer_name]=1
            
    protocols=list(layers.keys())
    values=list(layers.values())
    plt.bar(range(len(protocols)), values,tick_label=protocols)
    print(protocols)
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Protocol Distribution')
    plt.show()

if __name__=="__main__":
    listInterfaces()
    getWhiteListIPs()
    capture=captureData("")
    #printAllPackets(capture)
    #printUnknownPackets(capture)
    prettyPrintProtocolsChart(capture)
    

