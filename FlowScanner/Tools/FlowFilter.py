"""
Module to filter server IP's from (Net)Flow
"""
#! /usr/bin/env python

import os
from os import path
import sys
import ipaddress
from typing import Dict
import requests

class FlowFilter:
    """
    Class
    """
    ports: Dict[str, Dict[int, float]] = {}
    ports_dict_filled = False
    ip_port_dict = [ ]

    def ServerFilter(self, flowlist: list):
        """
        Func
        """
        for flow in flowlist:
            if flow.ip_source.is_multicast:
                continue
            if flow.ip_dest.is_multicast:
                continue
            if flow.ip_source == ipaddress.ip_address("255.255.255.255"):
                continue
            if flow.ip_dest == ipaddress.ip_address("255.255.255.255"):
                continue

            match self.NmapPortLogic(flow.port_source, flow.port_dest, flow.proto):
                case 1:
                    self.AddIPToList(flow.ip_source, flow.port_source)
                case 0:
                    ##More magic (if this event will occur, not sure yet, test with more data)
                    print("We need more magic!")
                    print(flow)
                case -1:
                    self.AddIPToList(flow.ip_dest, flow.port_dest)
        return self.ip_port_dict

    def LoadNMAPServices(self) -> None:
        """
        Func
        """
        if not path.exists(os.getenv('nmap_services_file_location')):
            print("Nmap file not found, trying to fetch new one from the internet...")
            try:
                url = os.getenv('nmap_web_file_url',
                                "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services")
                req = requests.get(url, allow_redirects=True)
                with open(os.getenv('nmap_services_file_location'), 'wb').write(req.content):
                    print("File downloading...")
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
        Func
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

    def AddIPToList(self, ip_address, port) -> None:
        """
        Func
        """
        searchresult = next((item for item in self.ip_port_dict
                            if item["ipaddress"] == ip_address), None)
        if searchresult is None:
            temp_dict = { "ipaddress": ip_address, "portlist": [ port ] }
            self.ip_port_dict.append(temp_dict)
        else:
            if not port in searchresult["portlist"]:
                searchresult["portlist"].append(port)
