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
from FlowScanner.Tools.Scans import PerformScans
from FlowScanner.Parser.Nfdump import Nfdump

if __name__ == "__main__":
    load_dotenv()
    patterns = ["*"]
    my_event_handler = PatternMatchingEventHandler(patterns, None, False, True)

def OnCreated(event):
    """
    docstring
    """
    nfdump = Nfdump(event.src_path)
    flow_filter = FlowFilter()

    flow_list = nfdump.Filter()
    server_list = flow_filter.ServerFilter(flow_list)
    PerformScans(server_list)
    os.remove(event.src_path)

my_event_handler.on_created = OnCreated

PATH = "/home/marvin/Bureaublad/FlowScanner/Files/Flows"
flow_file_observer = Observer()
flow_file_observer.schedule(my_event_handler, PATH, False)

flow_file_observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    flow_file_observer.stop()
    flow_file_observer.join()
