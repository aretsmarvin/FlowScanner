"""
Main module with file observer for FlowScanner
"""

#! /usr/bin/env python

import os
import time
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from FlowScanner.Tools.FlowFilter import FlowFilter
from FlowScanner.Tools.ScanFilter import ScanFilter
from FlowScanner.Tools.Scans import PerformScans
from FlowScanner.Parser.Nfdump import Nfdump

if __name__ == "__main__":
    load_dotenv()
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
    PerformScans(server_list)
    os.remove(event.src_path)

new_flow_file_handler.on_created = OnCreated

PATH = os.getenv('flow_files_folder')
flow_file_observer = Observer()
flow_file_observer.schedule(new_flow_file_handler, PATH, False)

flow_file_observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    flow_file_observer.stop()
    flow_file_observer.join()
