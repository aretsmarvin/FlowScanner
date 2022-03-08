"""
Main module for FlowScanner
"""

#! /usr/bin/env python

import os
from os import path
import sys
from dotenv import load_dotenv
from FlowScanner.Tools.FlowFilter import FlowFilter
from FlowScanner.Tools.Scans import Scans
from FlowScanner.Parser.Nfdump import Nfdump

def main() -> None:
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

    nfdump = Nfdump(os.getenv('flow_file_location'))
    flow_filter = FlowFilter()
    scans = Scans()

    flow_list = nfdump.Filter()
    server_list = flow_filter.ServerFilter(flow_list)
    scans.Perform(server_list)
    print(server_list)


if __name__ == "__main__":
    main()
