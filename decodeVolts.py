#!/usr/bin/env python3
from argparse import ArgumentParser
import sys

def decodeVolts(hexString):
    volts = 0

    # Make sure supplied String is long enough
    if len(hexString):
        return None

    #MSB
    bytes = hexString[6:7], hexString[4:5], hexString[2:2], hexString[0:1]
    print (bytes)
    return 3


parser = ArgumentParser(description='BM Voltage Decode Utility')
parser.add_argument('-h', '--hexVolts', help='Hex encoded voltage measurement', default='00006240')
args = parser.parse_args()

if len(args.hexVolts) != 8:
    print('Hex encoded value must be 4 bytes long')
    sys.exit(1)

print(decodeVolts(args.hexVolts))
