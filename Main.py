"""
Main module for FlowScanner
"""

#! /usr/bin/env python

import os
from os import path
import sys
from dotenv import load_dotenv
from FlowScanner.Tools.FlowFilter import FlowFilter
from FlowScanner.Tools.Scans import PerformScans
from FlowScanner.Parser.Nfdump import Nfdump

def Main() -> None:
    """
    Main function for FlowScanner
    """
    load_dotenv()
    if not path.exists(os.getenv('flow_file_location', "")):
        print("Flow file does not exist: "
                + str(os.getenv('flow_file_location'))
                + " - Leaving...!")
        sys.exit(1)
    print("Flow to nmap tool")
    print("Welcome.............")
    print()

    nfdump = Nfdump()
    flow_filter = FlowFilter()

    flow_list = nfdump.Filter(os.getenv('flow_file_location'))
    server_list = flow_filter.ServerFilter(flow_list)
    PerformScans(server_list)

if __name__ == "__main__":
    Main()
