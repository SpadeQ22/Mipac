import scapy.all as scapy
import sys


class Scanner:

    def __init__(self):
        pass

    def scan(self, ip):
        ARP = scapy.ARP(pdst=ip)
        Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = Ether / ARP
        ans = scapy.srp(packet, timeout=1, verbose=False)[0]
        client_list = []
        for element in ans:
            client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
            client_list.append(client_dict)
        return client_list


    def print_output(self, client_list):
        print("IP Address \t\t\t MAC Addresses \n -------------------------------------------------------")
        for client in client_list:
            print(client["IP"] + "\t\t\t" + client["MAC"])

    def run(self, ip):
        client_list = self.scan(ip)
        self.print_output(client_list)

ip = "192.168.1.1/24"

scan  = Scanner()
scan.run(ip)