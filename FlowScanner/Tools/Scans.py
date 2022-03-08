"""
Module to perform the scans
"""
#! /usr/bin/env python
from multiprocessing.pool import ThreadPool
import subprocess

class Scans:
    """
    The Scans class is responsible for performing the actual scans. It uses
    subprocesses to run multiple scans simultaneously
    """

    def Perform(self, server_list) -> None:
        """
        TODO: fill this
        """
        num = None
        thread_pool = ThreadPool(num)
        for server in server_list:
            thread_pool.apply_async(self.ScanWorker,
                                    (server.get('ip_version'),
                                       server.get('ipaddress'),
                                       server.get('portlist'),))

        thread_pool.close()
        thread_pool.join()


    def ScanWorker(self, ip_version, ip_address, port_list):
        """
        TODO: fill this
        """
        command = ['nmap', str(ip_address), '-p', ','.join(port_list), '-Pn']
        if ip_version == "IPv6":
            command.append('-6')

        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:
            sub.wait()
            print(sub)
            for stdout_line in iter(sub.stdout.readline, ""):
                if stdout_line:
                    print(stdout_line)
                else:
                    return
