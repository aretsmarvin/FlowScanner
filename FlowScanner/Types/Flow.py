"""
Module that represents a 'Flow' type
"""

#! /usr/bin/env python

from typing import NamedTuple
import netaddr

class Flow(NamedTuple):
    """
    Class that represents a 'Flow' type
    """
    ip_version: str
    proto: str
    ip_source: netaddr.IPAddress
    port_source: int
    ip_dest: netaddr.IPAddress
    port_dest: int
    flags: str
