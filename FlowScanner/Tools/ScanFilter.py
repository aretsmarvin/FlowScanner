"""
Module to filter out IP addresses and ports
that have been scanned less than a hour ago.
"""
#! /usr/bin/env python

import logging
import os
from datetime import datetime

from FlowScanner.Database import MySQL

class ScanFilter:
    """
    The FlowFilter class is responsible for filtering the server
    IP's and port out of the flow data.
    """

    def ScanTargetFilter(self, ip_ports_list: list):
        """
        Main function to filter the server IP's and corresponding ports
        returns a list of targets which are scanned longer than one
        hour ago.
        """
        for ip_ports in ip_ports_list:
            if ip_ports.get('portlist_tcp'):
                new_portlist = self.PortFilter(ip_ports.get('ipaddress'),
                                                ip_ports.get('portlist_tcp'),
                                                "TCP")
                ip_ports['portlist_tcp'] = new_portlist
            if ip_ports.get('portlist_udp'):
                new_portlist = self.PortFilter(ip_ports.get('ipaddress'),
                                                ip_ports.get('portlist_udp'),
                                                "UDP")
                ip_ports['portlist_udp'] = new_portlist
        loop_list = ip_ports_list.copy()
        for ip_ports in loop_list:
            if not ip_ports['portlist_tcp'] and not ip_ports['portlist_udp']:
                logging.debug('TCP and UDP portlist both empty for IP: %s',
                                ip_ports.get('ipaddress'))
                ip_ports_list.remove(ip_ports)
        return ip_ports_list

    @staticmethod
    def PortFilter(ip_address, port_list, proto):
        """
        Function to filter recently scanned ports from IP.
        """
        now = datetime.now()
        loop_list = port_list.copy()
        for port in loop_list:
            last_scan_time = MySQL.GetLastScanTime(
                        str(ip_address),
                        port,
                        proto)
            if last_scan_time is not None:
                if (now - last_scan_time[0]).total_seconds() < int(
                        os.getenv('min_scan_timeout_seconds', "3600")):
                    port_list.remove(port)
        return port_list
