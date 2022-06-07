![Python lint](https://github.com/aretsmarvin/FlowScanner/actions/workflows/pylint.yml/badge.svg)

# FlowScanner
This scanner is an internship (research) project for [SURF](https://surf.nl). It's purpose is to process [(Net)Flow](https://en.wikipedia.org/wiki/NetFlow) data into different types of network scans, like Nmap. By using flow data as an input for the scans, the scans will be much more specifc. Only ports that has been seen as open, will be scanned.

It also has an big advantage for IPv6 addresses. Since the IPv6 address space is much bigger than IPv4, it would usually almost be impossible to scan it. But when you use the NetFlow data as input for the scans. You know which IPv6 addresses and their corresponding ports are active.

## Get up and running
For the installation and usage of the scanner, please see [the WiKi](../../wiki). In here you will find everything to get started.
