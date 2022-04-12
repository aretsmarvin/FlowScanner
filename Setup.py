"""
Standard setup.py file. Run
$ python setup.py build
# python setup.py install
"""
#!/usr/bin/env python

from setuptools import setup, find_packages

from FlowScanner.Database import MySQL

VERSION = __import__("FlowScanner").VERSION

setup(name='FlowScanner',
      version=VERSION,
      description='Processes NetFlow data into Nmap scans.',
      author='Marvin Arets',
      author_email='marvin.arets@surf.nl',
      url='https://github.com/aretsmarvin/FlowScanner/',
      packages=find_packages(include=['FlowScanner', 'FlowScanner.*']),
      python_requires=">=3.10",
      install_requires=[
        "requests",
        "python-dotenv",
        "watchdog",
        "netaddr",
        "mysql-connector-python",
        ],
        scripts=['Bin/FlowScanner'],
)

MySQL.DatabaseSetup()
