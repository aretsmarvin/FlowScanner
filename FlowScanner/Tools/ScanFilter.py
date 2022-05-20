"""
Module to filter out IP addresses and ports
that have been scanned less than a hour ago.
"""
#! /usr/bin/env python

import os
from datetime import datetime

from FlowScanner.Database import MySQL

@staticmethod
def PortFilter(ip_address, port_list, proto):
    """
    Function to filter recently scanned ports from IP.
    """
    if port_list:
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
