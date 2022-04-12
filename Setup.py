"""
Standard setup.py file. Run
$ python setup.py build
# python setup.py install
"""
#!/usr/bin/env python
# pylint: skip-file

from setuptools import setup, find_packages

from FlowScanner.Database import MySQL
import distutils.log
from distutils.command.build_py import build_py as _build_py

VERSION = __import__("FlowScanner").VERSION

class build_py(_build_py):
    """Specialized Python source builder."""
    _build_py.announce(
    "Creation of MySQL database...",
    distutils.log.INFO)
    MySQL.DatabaseSetup()

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
        cmdclass={'build_py': build_py},
)
