# imports scapy Utility

from scapy.all import *
from scapy.utils import *

# variable to store hexdump

hexdump =  """
            0000  10 56 ca 6b e3 00 f8 4d 89 70 1b ba 08 00 45 00   .V.k...M.p....E.
            0010  pp00 40 00 00 40 00 40 06 b8 2a 0a cc 02 3e 80 77   .@..@.@..*...>.w
            0020  f5 0c d0 61 00 50 52 37 35 68 00 00 00 00 b0 02   ...a.PR75h......
            0030  ff ff 96 1b 00 00 02 04 05 b4 01 03 03 06 01 01   ................
            0040  08 0a d1 ea f4 16 00 00 00 00 04 02 00 00         ..............
        """
print(hexdump)

# Initialize a 802.11 structure from raw bytes

pkt_raw = import_hexcap(hexdump)
print(pkt_raw)

#scapy function to view the info

# packet.summary()
# packet.show()