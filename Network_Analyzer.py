# import all class
from Extractor.DHCP import DHCP
from Extractor.DNS import DNS
from Extractor.HTTP import HTTP
from Extractor.TCP import TCP
from Extractor.UDP import UDP
from Extractor.IP import IP

# load text hexdump
with open('hexdump.txt', 'r') as file:
    hexdump = file.read()
# modify the hexdump to remove the offset

# EtherNet Header
# IP Header
# UDP Header
# DNS Header