"""
Module to perform the scans
"""
#! /usr/bin/env python
from multiprocessing.pool import ThreadPool
import subprocess
import os

def PerformScans(server_list) -> None:
    """
    TODO: fill this
    """
    num = None
    thread_pool = ThreadPool(num)
    for server in server_list:
        thread_pool.apply_async(ScanWorker,
                                (server.get('ip_version'),
                                    server.get('ipaddress'),
                                    server.get('portlist_tcp'),
                                    server.get('portlist_udp'),))

    thread_pool.close()
    thread_pool.join()


def ScanWorker(ip_version, ip_address, port_list_tcp, port_list_udp):
    """
    TODO: fill this
    """
    if 'None' in port_list_tcp:
        port_list_tcp.remove('None')
    if 'None' in port_list_udp:
        port_list_udp.remove('None')

    if port_list_tcp:
        NmapTCPScan(ip_version, ip_address, ','.join(port_list_tcp))

    if port_list_udp:
        NmapUDPScan(ip_version, ip_address, ','.join(port_list_udp))

def NmapTCPScan(ip_version, ip_address, port_list):
    """
    TODO: fill this
    """
    command = ['nmap',
                '-sV',
                str(ip_address),
                '-p',
                port_list,
                '-oX',
                '/tmp/FlowScanner/output_tcp_' + str(ip_address) + '.xml']
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")

def NmapUDPScan(ip_version, ip_address, port_list):
    """
    TODO: fill this
    """
    command = ['nmap',
                '-sV',
                str(ip_address),
                '-p',
                port_list,
                '-sU',
                '-oX',
                '/tmp/FlowScanner/output_udp_' + str(ip_address) + '.xml',
                '--append-output']
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")
