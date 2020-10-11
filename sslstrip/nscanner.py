import scapy.all as scapy
from maclookup import ApiClient


class Scanner():

    def print_output(self, client_list):
        print(
            "IP Address \t\t\t MAC Addresses \t\t\tVendor\n -----------------------------------------------------------------------------------")
        for client in client_list:
            print(client["IP"] + "\t\t\t" + client["MAC"] + "\t\t" + client["Vendor"])


    def scan(self, ip):
        ARP = scapy.ARP(pdst=ip)
        Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = Ether / ARP
        ans = scapy.srp(packet, timeout=2, verbose=False)[0]
        client_list = []
        for element in ans:
            MAC = element[1].hwsrc
            vendor = ApiClient("at_yS7J9zWswF0lxuKHa6b3352LuTOTs")
            client_dict = {"IP": element[1].psrc, "MAC": MAC, "Vendor": str(vendor.get_vendor(MAC).decode())}
            client_list.append(client_dict)
        return client_list


    def run(self, ip):
        client_list = self.scan(ip)
        self.print_output(client_list)