"""
Python library
"""

__version__ = "0.0.1"
__author__ = 'Joris Wachsmuth'

from .ConnectionManager import\
    ConnectionManager,\
    StandardMessages,\
    InvalidIPString,\
    MessageToBig,\
    _string_to_ip_and_port
