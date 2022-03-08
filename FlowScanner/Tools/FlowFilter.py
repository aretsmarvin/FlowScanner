"""
Module to filter server IP's from (Net)Flow
"""
#! /usr/bin/env python

import os
from os import path
import sys
import ipaddress
from ipaddress import ip_network
from typing import Dict
import requests

class FlowFilter:
    """
    The FlowFilter class is responsible for filtering the server
    IP's and port out of the flow data.
    """
    ports: Dict[str, Dict[int, float]] = {}
    ports_dict_filled = False
    ip_port_dict = [ ]
    surf_nets = [ ]

    def __init__(self):
        if not path.exists(os.getenv('known_ip_nets_file')):
            print("IP address file does not exist at " + os.getenv('known_ip_nets_file'))
        try:
            ip_ranges = [ ]
            with open(os.getenv('known_ip_nets_file'), 'r', encoding="utf-8") as ip_file:
                for net in ip_file:
                    try:
                        ip_ranges.append(str(net.splitlines()[0]))
                    except ValueError:
                        continue
                self.surf_nets = [
                    (range(int(n.network_address), int(n.broadcast_address)), n)
                    for n in map(ip_network, ip_ranges)
                ]
        except (IOError, AttributeError, AssertionError):
            print("Something went wrong...")

    def ServerFilter(self, flowlist: list):
        """
        Main function to filter the server IP's and corresponding ports
        """
        for flow in flowlist:
            if flow.ip_source.is_multicast or flow.ip_source.is_link_local:
                continue
            if flow.ip_dest.is_multicast or flow.ip_dest.is_link_local:
                continue
            if flow.ip_source == ipaddress.ip_address("255.255.255.255"):
                continue
            if flow.ip_dest == ipaddress.ip_address("255.255.255.255"):
                continue

            match self.NmapPortLogic(flow.port_source, flow.port_dest, flow.proto):
                case 1:
                    self.AddIPToList(flow.ip_source, flow.port_source, flow.proto)
                case 0:
                    ##More magic (if this event will occur, not sure yet, test with more data)
                    print("We need more magic!")
                    print(flow)
                case -1:
                    self.AddIPToList(flow.ip_dest, flow.port_dest, flow.proto)
        return self.ip_port_dict

    def LoadNMAPServices(self) -> None:
        """
        Loads values from NMAP services file. Checks if the file
        exists on the disk. If not, it downloads a new one.
        """
        if not path.exists(os.getenv('nmap_services_file_location')):
            print("Nmap file not found, trying to fetch new one from the internet...")
            try:
                url = os.getenv('nmap_web_file_url',
                                "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services")
                req = requests.get(url, allow_redirects=True)
                with open(os.getenv('nmap_services_file_location'), 'wb') as nmapfile:
                    nmapfile.write(req.content)
            except IOError as exception:
                print("Cannot download file: " + str(exception))
                sys.exit(1)

        try:
            with open(os.getenv('nmap_services_file_location'), 'r', encoding="utf-8") as nmap_file:
                for line in nmap_file:
                    try:
                        _, ports, freqs = line.split("#", 1)[0].split(None, 3)
                        ports, proto = ports.split("/", 1)
                        port = int(ports)
                        freq = float(freqs)
                    except ValueError:
                        continue
                    self.ports.setdefault(proto, {})[port] = freq
                self.ports_dict_filled = True
        except (IOError, AttributeError, AssertionError):
            print("Something went wrong...")

    def NmapPortLogic(self, port1: int, port2: int, proto: str) -> int:
        """
        Function which checks with the NMAP common port file
        if it is a common port, and what is the probability.
        It returns: 1 when port1 is a server port. -1 when it cannot
        decide which is the server port. 1 when port2 is a server port.
        """
        if not self.ports_dict_filled:
            self.LoadNMAPServices()

        if self.ports_dict_filled:
            portlist = self.ports.get(proto.lower(), {})
            val1, val2 = portlist.get(int(port1), 0), portlist.get(int(port2), 0)
            cmpval = (val1 > val2) - (val1 < val2)
            if cmpval == 0:
                return (port2 > port1) - (port2 < port1)
        return cmpval

    def AddIPToList(self, ip_address, port, proto) -> None:
        """
        Function to add IP address, with port number to the list.
        Checks if IP already exists. If so, it also checks if the
        port already exsists with that IP address.
        """
        searchresult = next((item for item in self.ip_port_dict
                            if item["ipaddress"] == ip_address), None)
        if searchresult is None:
            if self.CheckSURFIP(ip_address):
                temp_dict = { "ipaddress": ip_address, "portlist": [ str(port) + "/"  + proto] }
                self.ip_port_dict.append(temp_dict)
        else:
            if not str(port) + "/" + proto in searchresult["portlist"]:
                searchresult["portlist"].append(str(port) + "/" + proto)

    def CheckSURFIP(self, ip_address) -> bool:
        """
        Function to check if the provided IP address belongs to SURF
        Ryturns a bool
        """
        ipaddr = int(ipaddress.ip_address(ip_address))

        results = [n for r, n in self.surf_nets if ipaddr in r]
        if results:
            return True

        return False
