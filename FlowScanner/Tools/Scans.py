"""
Module to perform the scans
"""
#! /usr/bin/env python

import os
import shutil
import subprocess
from multiprocessing.pool import ThreadPool

from FlowScanner.Database import MySQL


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

def ScanWorker(ip_version, ip_address, port_list_tcp, port_list_udp):
    """
    One worker, that performs a scan, per IP and corresponding ports.
    """
    if 'None' in port_list_tcp:
        port_list_tcp.remove('None')
    if 'None' in port_list_udp:
        port_list_udp.remove('None')

    os.mkdir(os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address))

    if port_list_tcp:
        NmapTCPScan(ip_version, ip_address, ','.join(port_list_tcp))
        for port in port_list_tcp:
            MySQL.InsertOrUpdateIPPort(str(ip_address), int(port), 'TCP')

    if port_list_udp:
        NmapUDPScan(ip_version, ip_address, ','.join(port_list_udp))
        for port in port_list_udp:
            MySQL.InsertOrUpdateIPPort(str(ip_address), int(port), 'UDP')

    command = ['ivre',
                'scan2db',
                '-c',
                'NetFlow',
                '-r',
                os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address)]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()

    command = ['ivre',
                'db2view',
                'nmap',
                '--category',
                'NetFlow']
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()

    shutil.rmtree(os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address), ignore_errors=True)

def NmapTCPScan(ip_version, ip_address, port_list):
    """
    Perfroms Nmap scan on the TCP ports.
    """
    command = ['nmap',
                '--script=auth,malware,vuln,' + os.getenv('nmap_custom_scripts'),
                '-sV',
                str(ip_address),
                '-p',
                port_list,
                '-T4',
                '--host-timeout',
                '60m',
                '-oX',
                os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address) + '/tcp.xml']
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")

def NmapUDPScan(ip_version, ip_address, port_list):
    """
    Performs Nmap scan on the UDP ports.
    """
    command = ['nmap',
                '--script=auth,malware,vuln,' + os.getenv('nmap_custom_scripts'),
                '-sV',
                str(ip_address),
                '-p',
                port_list,
                '-T4',
                '--host-timeout',
                '60m',
                '-sU',
                '-oX',
                os.getenv('nmap_tmp_output_folder') + '/' + str(ip_address) + '/udp.xml']
    if ip_version == "IPv6":
        command.append('-6')
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
        sub.wait()
        os.system("stty echo")
