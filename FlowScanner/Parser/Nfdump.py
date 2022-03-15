"""
Module to parse Nfdumpe'd files
"""
#! /usr/bin/env python

import netaddr
import re
from FlowScanner.Types.Flow import Flow

class Nfdump:
    """
    Nfdump class
    """
    flow_list = []

    def Filter(self, file_location):
        """
        Function to filter only UDP and TCP from an nfdump line
        """
        with open(file_location, 'r', encoding="utf-8") as file:
            ##Check if file contains nfdump's header row (if yes, skip first line)
            if not file.readline().startswith('Date'):
                file.seek(0, 0)

            while line := file.readline():
                data = line.split()
                proto = data[3]
                if proto in ('TCP', 'UDP'):
                    self.Parse(data)

            return self.flow_list

    def Parse(self, data):
        """
        Function to parse nfdump
        """
        proto = data[3]
        flags = data[7]
        ##IPv4 regex
        # pylint: disable=line-too-long
        if re.search(r"^((?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])(?:\.(?!\:)|)){4})\:(?!0)(\d{1,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$", data[4]):
            ip_version = "IPv4"
            ip_source, port_source = data[4].split(':')
            ip_dest, port_dest = data[6].split(':')
        else:
            ip_version = "IPv6"
            ip_source, port_source = data[4].rsplit('.', 1)
            ip_dest, port_dest = data[6].rsplit('.', 1)

        output = Flow(ip_version,
                    proto,
                    netaddr.IPAddress(ip_source),
                    int(port_source),
                    netaddr.IPAddress(ip_dest),
                    int(port_dest),
                    flags)
        self.flow_list.append(output)
