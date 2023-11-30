#!/usr/bin/env python3
import logging
import math
from struct import unpack
log = logging.getLogger('JKBMS-BT')


def crc8(byteData):
    '''
    Generate 8 bit CRC of supplied string
    '''
    CRC = 0
    # for j in range(0, len(str),2):
    for b in byteData:
        # char = int(str[j:j+2], 16)
        # print(b)
        CRC = CRC + b
        CRC &= 0xff
    return CRC



def Hex2Int(hexString):
    """
    Decode the first byte of a hexString to int
    """
    answer = hexString[0]
    log.debug(f"Hex {hexString} decoded to {answer}")

    return answer


def Hex2Str(hexString):
    """
    Return the hexString as ASCII representation of hex, ie 0x4a -> 4a
    """
    answer = ""
    for x in hexString:
        answer += f"{x:02x}"

    log.debug(f"Hex {hexString} decoded to {answer}")

    return answer

def LittleHex2Short(hexString):
    """
    Decode a 2 byte hexString to int (little endian coded)
    """
    # Make sure supplied String is the correct length
    if len(hexString) != 2:
        log.info(f"Hex encoded value must be 2 bytes long. Was {len(hexString)} length")
        return 0
    answer = unpack("<h", hexString)[0]
    log.debug(f"Hex {hexString} 2 byte decoded to {answer}")
    return answer

def LittleHex2Int(hexString):
    """
    Decode a 4 byte hexString to int (little endian coded)
    """
    # Make sure supplied String is the correct length
    if len(hexString) != 4:
        log.info(f"Hex encoded value must be 4 bytes long. Was {len(hexString)} length")
        return 0

    answer = unpack("<i", hexString)[0]
    log.debug(f"Hex {hexString} 4 byte decoded to {answer}")
    return answer

def LittleHex2UInt(hexString):
    """
    Decode a 4 byte hexString to Uint (little endian coded)
    """
    # Make sure supplied String is the correct length
    if len(hexString) != 4:
        log.info(f"Hex encoded value must be 4 bytes long. Was {len(hexString)} length")
        return 0

    answer = unpack("<I", hexString)[0]
    log.debug(f"Hex {hexString} 4 byte decoded to {answer}")
    return answer

def uptime(byteData):
    """
    Decode 3 hex bytes to a JKBMS uptime
    """
    # Make sure supplied String is the correct length
    log.debug("uptime defn")
    value = 0
    for x, b in enumerate(byteData):
        # b = byteData.pop(0)
        value += b * 256 ** x
        log.debug(f"Uptime int value {value} for pos {x}")
    daysFloat = value / (60 * 60 * 24)
    days = math.trunc(daysFloat)
    hoursFloat = (daysFloat - days) * 24
    hours = math.trunc(hoursFloat)
    minutesFloat = (hoursFloat - hours) * 60
    minutes = math.trunc(minutesFloat)
    secondsFloat = (minutesFloat - minutes) * 60
    seconds = round(secondsFloat)
    uptime = f"{days}D{hours}H{minutes}M{seconds}S"
    log.info(f"Uptime result {uptime}")
    return uptime