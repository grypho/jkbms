#!/usr/bin/env python3
import logging
import math
from struct import unpack, calcsize
log = logging.getLogger('JKBMS-BT')

DATA_UINT8 = "<B"
DATA_INT16 = "<h"
DATA_UINT16 = "<H"
DATA_INT32 = "<l"
DATA_UINT32 = "<L"
DIV1000 = ":r/1000"
DIV10 = ":r/10"
DATA_UINT16_DIV1000 = DATA_UINT16 + DIV1000
DATA_INT16_DIV10 = DATA_INT16 + DIV10
DATA_UINT32_DIV1000 = DATA_UINT32 + DIV1000
DATA_INT32_DIV1000 = DATA_INT32 + DIV1000

DATA_ASCII = "ASCII"

EVERY5TH = 5
EVERY10TH = 10
EVERY60TH = 60

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

def Hex2Ascii(hexString):
    """
    Return the hexString as ASCII, ie 0x4a -> J
    """
    answer = ""
    for x in hexString:
        if x != 0:
            # Ignore 0x00 results
            answer += f"{x:c}"

    log.debug(f"Hex {hexString} decoded to {answer}")

    return answer

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
    answer = unpack(DATA_INT16, hexString)[0]
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

    answer = unpack(DATA_INT32, hexString)[0]
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

    answer = unpack(DATA_UINT32, hexString)[0]
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
    return value
#    daysFloat = value / (60 * 60 * 24)
#    days = math.trunc(daysFloat)
#    hoursFloat = (daysFloat - days) * 24
#    hours = math.trunc(hoursFloat)
#    minutesFloat = (hoursFloat - hours) * 60
#    minutes = math.trunc(minutesFloat)
#    secondsFloat = (minutesFloat - minutes) * 60
#    seconds = round(secondsFloat)
#    uptime = f"{days}D{hours}H{minutes}M{seconds}S"
#    log.info(f"Uptime result {uptime}")
#    return uptime


def DecodeFormat(fmt, hexString):
    # Make sure supplied String is the correct length
    if len(fmt) != 2:
        log.error(f"Invalid format {fmt}!")

    size = calcsize(fmt)
    if len(hexString) != size:
        log.info(f"Hex encoded value must be {size} bytes long. Was {len(hexString)} length")
        return 0
    answer = unpack(fmt, hexString)[0]
    log.debug(f"Hex {hexString} {size} byte decoded to {answer}")
    return answer
