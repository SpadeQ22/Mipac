import scapy.all as scapy


class Scanner():
    def __init__(self, ):
        pass

    def broadcast(self, ip):
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
        client_list = self.broadcast(ip)
        self.print_output(client_list)
