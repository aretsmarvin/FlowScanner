"""
Module that represents a 'Flow' type
"""

#! /usr/bin/env python

from typing import NamedTuple
import ipaddress

class Flow(NamedTuple):
    """
    Class that represents a 'Flow' type
    """
    proto: str
    ip_source: ipaddress.ip_address
    port_source: int
    ip_dest: ipaddress.ip_address
    port_dest: int
    flags: str
