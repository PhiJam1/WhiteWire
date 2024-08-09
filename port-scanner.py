import nmap 
from enum import Enum
from typing import List
DELIMITER = "<<------------------------------------- ^^ ------------------------------------->>\n" 

class ScanTypes(Enum):
    NONE = 0
    TCP_BASIC = 1
    TCP_INCOGNITO = 2
    TCP_INVISIBLE = 3
    UDP = 4

class PortScanner():

    def __init__(self):
        self.target_ip = ""
        self.port_range = ""
        self.scan_type = ScanTypes.NONE
        self.nm = nmap.PortScanner()
    
    def GetScanInfo(self):
        print("We'll need to collect some scanning info")
        self.target_ip = input("Enter IP address or url to scan: ")
        self.port_range = input("Enter port range (Enter 'FULL' for a full scan): ")
        print("Select the scan type")
        i = 0
        for scan in ScanTypes:
            if i == 0:
                i += 1
                continue
            print(str(i) + ") " + scan.name)
            i += 1
        self.scan_type = input("Select: ")

    def StartScan(self):
        if (self.target_ip == "" or self.port_range == "" or self.scan_type == ScanTypes.NONE):
            print("Error: Please enter all required information regarding this scan!")
            print(DELIMITER)
            return
        if (int(self.scan_type) == ScanTypes.TCP_BASIC.value):
            self.TcpBasicScan()
    
    def TcpBasicScan(self):
        flags = ""
        if self.port_range == "FULL":    
            print(f"Performing TCP Connect Scan on {self.target_ip} for all ports. Please Wait...")
            flags = '-sT -p- '
        else:
            print(f"Performing TCP Connect Scan on {self.target_ip} for ports {self.port_range}. Please Wait...")
            flags = '-sT -p '
        self.nm.scan(self.target_ip, arguments=flags + self.port_range)
        self.print_scan_results()

    def TcpStealthScan(self):
        flags = ""
        if self.port_range == "FULL":    
            print(f"Performing TCP Connect Stealth Scan on {self.target_ip} for all ports. Please Wait...")
            flags = '-sS -p- '
        else:
            print(f"Performing TCP Connect Stealth Scan on {self.target_ip} for ports {self.port_range}. Please Wait...")
            flags = '-sS -p '
        self.nm.scan(self.target_ip, arguments=flags + self.port_range)
        self.print_scan_results() 

    def ComprehensiveScan(self):
        flags = ""
        if self.port_range == "FULL":    
            print(f"Performing Comprehensive Scan on {self.target_ip} for all ports. Please Wait...")
            flags = '-A -p- '
        else:
            print(f"Performing Comprehensive Scan on {self.target_ip} for ports {self.port_range}. Please Wait...")
            flags = '-A -p '
        self.nm.scan(self.target_ip, arguments=flags + self.port_range)
        self.print_scan_results() 
    
    
    def print_scan_results(self):
        hosts = self.nm.all_hosts()
        if (len(hosts) != 1 or self.nm[hosts[0]].state() != "up"):
            print(f"Error: Could not find that IP Address. Please check that {self.target_ip} is a valid IP address and is serving requests.")
            return
        host = hosts[0]
        print(f"Host: {host} ({self.nm[host].hostname()})")
        print(f"State: {self.nm[host].state()}")
        for proto in self.nm[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = self.nm[host][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {self.nm[host][proto][port]['state']}")
    
tmp = PortScanner()
tmp.GetScanInfo()
tmp.StartScan()