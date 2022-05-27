"""
Module to perform the scans
"""
#! /usr/bin/env python

import logging
import os
import shutil
import subprocess
from multiprocessing.pool import ThreadPool

from ivre.db import db
from ivre.view import nmap_record_to_view

from FlowScanner.Database import MySQL
from FlowScanner.Tools import ScanFilter

def PerformScans(server_list) -> None:
    """
    Starts scan workers, based on the provided server list.
    Uses system resources according to availability.
    """
    num = None
    thread_pool = ThreadPool(num)
    for server in server_list:
        thread_pool.apply_async(ScanWorker,
                                (server.get('ip_version'),
                                    server.get('ipaddress'),
                                    server.get('portlist_tcp'),
                                    server.get('portlist_udp'),))
                                    ##, timeout=3600

    thread_pool.close()
    thread_pool.join()

def IVREInsertView(record):
    """
    Callback function to insert values
    to IVRE view.
    """
    db.view.start_store_hosts()
    db.view.store_or_merge_host(nmap_record_to_view(record))
    db.view.stop_store_hosts()

def ScanWorker(ip_version, ip_address, port_list_tcp, port_list_udp):
    """
    One worker, that performs a scan, per IP and corresponding ports.
    """
    logging.debug('New scan worker for IP: %s, TCP ports: %s, UDP ports: %s',
                    str(ip_address),
                    str(port_list_tcp),
                    str(port_list_udp))

    os.mkdir(os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address))

    port_list_tcp = ScanFilter.PortFilter(ip_address, port_list_tcp, "TCP")
    NmapTCPScan(ip_version, ip_address, port_list_tcp)
    for port in port_list_tcp:
        MySQL.InsertOrUpdateIPPort(str(ip_address), int(port), 'TCP')

    port_list_udp = ScanFilter.PortFilter(ip_address, port_list_udp, "UDP")
    NmapUDPScan(ip_version, ip_address, port_list_udp)
    for port in port_list_udp:
        MySQL.InsertOrUpdateIPPort(str(ip_address), int(port), 'UDP')

    db.nmap.store_scan(os.path.join(os.getenv('nmap_tmp_output_folder'),
                                                str(ip_address)),
                        categories=["NetFlow"],
                        source="FlowScanner",
                        callback=IVREInsertView)

    shutil.rmtree(os.path.join(os.getenv('nmap_tmp_output_folder'),
                    str(ip_address)),
                    ignore_errors=True)
    logging.debug('End worker for IP: %s, TCP ports: %s, UDP ports: %s',
                    str(ip_address),
                    str(port_list_tcp),
                    str(port_list_udp))

def NmapTCPScan(ip_version, ip_address, port_list):
    """
    Perfroms Nmap scan on the TCP ports.
    """
    if not port_list:
        logging.debug('Nmap TCP scan called with empty port_list')
        return
    logging.info('Nmap TCP scan IP: %s port(s): %s',
                str(ip_address),
                str(port_list))
    command = ['nmap',
                '--script=auth,' + os.getenv('nmap_custom_scripts', ''),
                '-sV',
                str(ip_address),
                '-p',
                str(port_list),
                '-T4',
                '--host-timeout',
                '60m',
                '-oX',
                os.path.join(os.getenv('nmap_tmp_output_folder'),
                                        str(ip_address),
                                        'tcp.xml')]
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")
    logging.info('End Nmap TCP scan IP: %s port(s): %s',
                str(ip_address),
                str(port_list))

def NmapUDPScan(ip_version, ip_address, port_list):
    """
    Performs Nmap scan on the UDP ports.
    """
    if not port_list:
        logging.debug('Nmap UDP scan called with empty port_list')
        return
    logging.info('Nmap UDP scan IP: %s port(s): %s',
                str(ip_address),
                str(port_list))
    command = ['nmap',
                '--script=auth,' + os.getenv('nmap_custom_scripts', '') ,
                '-sV',
                str(ip_address),
                '-p',
                str(port_list),
                '-T4',
                '--host-timeout',
                '60m',
                '-sU',
                '-oX',
                os.path.join(os.getenv('nmap_tmp_output_folder'),
                                        str(ip_address),
                                        'udp.xml')]
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")
    logging.info('End Nmap UDP scan IP: %s port(s): %s',
                str(ip_address),
                str(port_list))
