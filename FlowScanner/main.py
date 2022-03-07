"""
Main module for FlowScanner
"""

#! /usr/bin/env python

import os
import sys
from os import path
from dotenv import load_dotenv

def main() -> None:
    """
    Main function for FlowScanner
    """
    load_dotenv()
    if not path.exists(os.getenv('flow_file_location', "")):
        print("Flow file does not exist: "
                + str(os.getenv('flow_file_location'))
                + " - Leaving...!")
        sys.exit()

if __name__ == "__main__":
    main()
