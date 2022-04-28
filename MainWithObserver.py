"""
Main module with file observer for FlowScanner
"""

#! /usr/bin/env python

import os
import time
import logging

import dotenv
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer

from FlowScanner.Database import MySQL
from FlowScanner.Parser.Nfdump import Nfdump
from FlowScanner.Tools.FlowFilter import FlowFilter
from FlowScanner.Tools.ScanFilter import ScanFilter
from FlowScanner.Tools.Scans import PerformScans

logging.basicConfig(filename='FlowScanner.log', encoding='utf-8', level=logging.DEBUG)

if __name__ == "__main__":
    dotenv.load_dotenv('.env')
    patterns = ["*"]
    new_flow_file_handler = PatternMatchingEventHandler(patterns, None, False, True)
    nfdump = Nfdump()
    flow_filter = FlowFilter()
    scan_filter = ScanFilter()

def OnCreated(event):
    """
    Event handler for when new file is created. Waits untill creation of
    file is completely done.
    """
    last_modified = os.path.getmtime(event.src_path)
    while last_modified is not None:
        current = os.path.getmtime(event.src_path)
        time.sleep(1)
        if current == last_modified:
            last_modified = None
    flow_list = None
    server_list = None
    flow_list = nfdump.Filter(event.src_path)
    server_list = flow_filter.ServerFilter(flow_list)
    scan_list = scan_filter.ScanTargetFilter(server_list)
    PerformScans(scan_list)
    os.remove(event.src_path)

new_flow_file_handler.on_created = OnCreated

PATH = os.getenv('flow_files_folder')
flow_file_observer = Observer()
flow_file_observer.schedule(new_flow_file_handler, PATH, False)

flow_file_observer.start()

print(MySQL.GetLastScanTime("192.168.1.10", 22, "TCP"))

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    flow_file_observer.stop()
    flow_file_observer.join()
