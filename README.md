![Python lint](https://github.com/aretsmarvin/FlowScanner/actions/workflows/pylint.yml/badge.svg)

# FlowScanner
This scanner is a internship (research) project for [SURF](https://surf.nl). It's purpose is to process [(Net)Flow](https://en.wikipedia.org/wiki/NetFlow) data into different types of network scans, like Nmap. By using Flow data as an input for the scans, the scans will be much more specifc. Only ports that has been seen as open, will be scanned.
It also has an big advantage for IPv6 addresses. Since the IPv6 address space is much bigger than IPv4, it would usually almost be impossible to scan it. But when you use the netflow data as input for the scans. You know which IPv6 addresses and their corresponding ports are active.

## Requirements

IMPORTANT: The script requires Python 3.10 (or higher), any older version will not work!

## Installation

```bash
$ pip3 install -r requirements.txt
```

## Configuration

Copy and rename the `.env.example` file to `.env` and change it's values.