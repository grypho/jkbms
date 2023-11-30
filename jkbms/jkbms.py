#!/usr/bin/env python3
from bluepy import btle
import logging
import math
from .publishMqtt import publishMqtt as publish
from struct import unpack
import paho.mqtt.publish as publishToMqtt

from .jkbmsdecode import crc8, Hex2Str,LittleHex2Short, Hex2Int, LittleHex2UInt, LittleHex2Int, uptime

class hexdump:
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def __iter__(self):
        last_bs, last_line = None, None
        for i in range(0, len(self.buf), 16):
            bs = bytearray(self.buf[i : i + 16])
            line = "{:08x}  {:23}  {:23}  |{:16}|".format(
                self.off + i,
                " ".join(("{:02x}".format(x) for x in bs[:8])),
                " ".join(("{:02x}".format(x) for x in bs[8:])),
                "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
            )
            if bs == last_bs:
                line = "*"
            if bs != last_bs or line != last_line:
                yield line
            last_bs, last_line = bs, line
        yield "{:08x}".format(self.off + len(self.buf))

    def __str__(self):
        return "\n".join(self)

    def __repr__(self):
        return "\n".join(self)
    
EXTENDED_RECORD = 1
CELL_DATA = 2
INFO_RECORD = 3

getInfo = b'\xaa\x55\x90\xeb\x97\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11'
getCellInfo = b'\xaa\x55\x90\xeb\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'

InfoResponseMapping = [
    ["Hex2Str", 4, "Header", ""],
    ["Hex2Str", 1, "Record Type", ""],
    ["Hex2Int", 1, "Record Counter", ""],
    ["Hex2Ascii", 16, "Device Model", ""],
    ["Hex2Ascii", 8, "Hardware Version", ""],
    ["Hex2Ascii", 8, "Software Version", ""],
    ["uptime", 4, "Up Time", ""],
    ["Hex2Int", 4, "Power-on Times", ""],
    ["Hex2Ascii", 16, "Device Name", ""],
    ["Hex2Ascii", 16, "Device Passcode", ""],
    ["Hex2Ascii", 8, "Manufacturing Date", ""],
    ["Hex2Ascii", 11, "Serial Number", ""],
    ["Hex2Ascii", 5, "Passcode", ""],
    ["Hex2Ascii", 16, "User Data", ""],
    ["Hex2Ascii", 16, "Setup Passcode", ""],
    ["discard", 672, "unknown", ""],
]

CellInfoResponseMapping = [
    ("Hex2Str", 4, "Header", ""),
    ("Hex2Str", 1, "Record_Type", ""),
    ("Hex2Int", 1, "Record_Counter", ""),
    ("LittleHex2Short:r/1000", 2, "VoltageCell01", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell02", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell03", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell04", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell05", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell06", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell07", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell08", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell09", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell10", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell11", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell12", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell13", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell14", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell15", "V"),
    ("LittleHex2Short:r/1000", 2, "VoltageCell16", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell17", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell18", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell19", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell20", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell21", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell22", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell23", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell24", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell25", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell26", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell27", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell28", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell29", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell30", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell31", "V"),
    ("LittleHex2Short:r/1000", 2, "-VoltageCell32", "V"),
    ("Hex2Str", 4, "EnabledCellsBitmask", ""), #0xFF000000 => 8 cells, 0xFF010000 => 9 cells, ..., 0xFFFF0000 => 16cells
    ("LittleHex2Short:r/1000", 2, "AverageCellVoltage", "V"),
    ("LittleHex2Short:r/1000", 2, "DeltaCellVoltage", "V"),
    ("LittleHex2Short:r/1000", 2, "CurrentBalancer", "A"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell01", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell02", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell03", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell04", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell05", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell06", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell07", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell08", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell09", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell10", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell11", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell12", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell13", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell14", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell15", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "ResistanceCell16", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell17", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell18", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell19", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell20", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell21", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell22", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell23", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell24", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell25", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell26", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell27", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell28", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell29", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell30", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell31", "Ohm"),
    ("LittleHex2Short:r/1000", 2, "-ResistanceCell32", "Ohm"),
    ("Hex2Str", 6, "-discard2", ""),
    ("LittleHex2UInt:r/1000", 4, "BatteryVoltage", "V"),
    ("LittleHex2UInt:r/1000", 4, "BatteryPower", "W"),
    ("LittleHex2Int:r/1000", 4, "BalanceCurrent", "A"),  # signed int32
    # ("discard", 8, "discard3", ""),
    ("LittleHex2Short:r/10", 2, "BatteryT1", "°C"),
    ("LittleHex2Short:r/10", 2, "BatteryT2", "°C"),
    ("LittleHex2Short:r/10", 2, "MOSTemp", "°C"),
    ("Hex2Str", 2, "-Unknown3", ""), #0x0001 charge overtemp, 0x0002 charge undertemp. 0x0008 cell undervoltage, 0x0400 cell count error, 0x0800 current sensor anomaly, 0x1000 cell overvoltage
    ("Hex2Str", 2, "-discard4", ""),  # discard4
    ("Hex2Str", 1, "-discard4_1", ""),  # added
    ("Hex2Int", 1, "Percent_Remain", "%"),
    ("LittleHex2UInt:r/1000", 4, "CapacityRemain", "Ah"),  # Unknown6+7
    ("LittleHex2UInt:r/1000", 4, "NominalCapacity", "Ah"),  # Unknown8+9
    ("LittleHex2UInt", 4, "CycleCount", ""),
    # ("discard", 2, "Unknown10", ""),
    # ("discard", 2, "Unknown11", ""),
    ("LittleHex2UInt:r/1000", 4, "CycleCapacity", "Ah"),  # Unknown10+11
    ("Hex2Str", 2, "-Unknown12", ""),
    ("Hex2Str", 2, "-Unknown13", ""),
    ("uptime", 3, "Time", ""),
    ("Hex2Str", 2, "-Unknown15", ""),
    ("Hex2Str", 2, "-Unknown16", ""),
    ("Hex2Str", 2, "-Unknown17", ""),
    ("Hex2Str", 12, "-discard6", ""),
    ("Hex2Str", 2, "-Unknown18", ""),
    ("Hex2Str", 2, "-Unknown19", ""),
    ("Hex2Str", 2, "-Unknown20", ""),
    ("LittleHex2Short:r/1000", 2, "CurrentCharge", "A"),  # Unknown21
    ("LittleHex2Short:r/1000", 2, "CurrentDischarge", "A"),  # Unknown22
    ("Hex2Str", 2, "-Unknown23", ""),
    ("Hex2Str", 2, "-Unknown24", ""),
    ("Hex2Str", 2, "-Unknown25", ""),
    ("Hex2Str", 2, "-Unknown26", ""),
    ("Hex2Str", 2, "-Unknown27", ""),
    ("Hex2Str", 2, "-Unknown28", ""),
    ("Hex2Str", 2, "-Unknown29", ""),
    ("Hex2Str", 4, "-Unknown30", ""),
    ("Hex2Str", 4, "-Unknown31", ""),
    ("Hex2Str", 4, "-Unknown32", ""),
    ("Hex2Str", 4, "-Unknown33", ""),
    ("Hex2Str", 4, "-Unknown34", ""),
    ("Hex2Str", 4, "-Unknown35", ""),
    ("Hex2Str", 4, "-Unknown36", ""),
    ("Hex2Str", 4, "-Unknown37", ""),
    ("Hex2Str", 4, "-Unknown38", ""),
    ("Hex2Str", 4, "-Unknown39", ""),
    ("Hex2Str", 4, "-Unknown40", ""),
    ("Hex2Str", 4, "-Unknown41", ""),
    ("discard", 45, "-UnknownXX", ""),
]

log = logging.getLogger('JKBMS-BT')

SOR = bytes.fromhex("55aaeb90")

class jkBmsDelegate(btle.DefaultDelegate):
    '''
    BLE delegate to deal with notifications (information) from the JKBMS device
    '''
    # JSBMS hat bei getCellInfo 0x02 und bei getInfo 0x03
    def __init__(self, jkbms):
        btle.DefaultDelegate.__init__(self)
        # extra initialisation here
        self.jkbms = jkbms
        print('Delegate {}'.format(str(jkbms)))
        self.notificationData = bytearray()
        self.record_type = None


    def is_record_start(self, record):
        if record.startswith(SOR):
#            log.debug("SOR found in record")
            return True
        return False

    def recordIsComplete(self, record):
        """"""
        # check record starts with 'SOR'
        if not self.is_record_start(self.notificationData):
            self.notificationData = bytearray()
            log.debug("No SOR found in record looking for completeness")
            return False
        # check that length one of the valid lengths (300, 320)
        if len(self.notificationData) == 100 or len(self.notificationData) >= 300:
            # check the crc/checksum is correct for the record data
            crc = ord(self.notificationData[-1:])
            calcCrc = crc8(self.notificationData[:-1])
            print (crc, calcCrc, "len ", len(self.notificationData))
            print(hexdump(self.notificationData))
            if crc == calcCrc:
                log.debug("Record CRC is valid")
                return True
        return False

    def processInfoRecord(self, record):
        log.info('Processing info record')
        del record[0:5]
        counter = record.pop(0)
        log.info('Record number: {}'.format(counter))
        vendorID = bytearray()
        hardwareVersion = bytearray()
        softwareVersion = bytearray()
        uptime = 0
        powerUpTimes = 0
        deviceName = bytearray()
        passCode = bytearray()
        # start at byte 7, go till 0x00 for device model
        while len(record) > 0:
            _int = record.pop(0)
            # print (_int)
            if _int == 0x00:
                break
            else:
                vendorID += bytes(_int.to_bytes(1, byteorder='big'))
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # process hardware version
        hardwareVersion += bytes(_int.to_bytes(1, byteorder='big'))
        while len(record) > 0:
            _int = record.pop(0)
            # print (_int)
            if _int == 0x00:
                break
            else:
                hardwareVersion += bytes(_int.to_bytes(1, byteorder='big'))
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # process software version
        softwareVersion += bytes(_int.to_bytes(1, byteorder='big'))
        while len(record) > 0:
            _int = record.pop(0)
            # print (_int)
            if _int == 0x00:
                break
            else:
                softwareVersion += bytes(_int.to_bytes(1, byteorder='big'))
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # process uptime version
        upTimePos = 0
        uptime = _int * 256**upTimePos
        while len(record) > 0:
            _int = record.pop(0)
            upTimePos += 1
            # print (_int)
            if _int == 0x00:
                break
            else:
                uptime += _int * 256**upTimePos
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # power up times
        powerUpTimes = _int
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # device name
        deviceName += bytes(_int.to_bytes(1, byteorder='big'))
        while len(record) > 0:
            _int = record.pop(0)
            # print (_int)
            if _int == 0x00:
                break
            else:
                deviceName += bytes(_int.to_bytes(1, byteorder='big'))
        # consume remaining null bytes
        _int = record.pop(0)
        while _int == 0x00:
            _int = record.pop(0)
        # Passcode
        passCode += bytes(_int.to_bytes(1, byteorder='big'))
        while len(record) > 0:
            _int = record.pop(0)
            # print (_int)
            if _int == 0x00:
                break
            else:
                passCode += bytes(_int.to_bytes(1, byteorder='big'))

        log.info('VendorID: {}'.format(vendorID.decode('utf-8')))
        publish({'VendorID': vendorID.decode('utf-8')}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)
        log.info('Device Name: {}'.format(deviceName.decode('utf-8')))
        publish({'DeviceName': deviceName.decode('utf-8')}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)
        log.debug('Pass Code: {}'.format(passCode.decode('utf-8')))
        # publish({'PassCode': passCode.decode('utf-8')}, format=self.jkbms.format, broker=self.jkbms.mqttBroker)
        log.info('Hardware Version: {}'.format(hardwareVersion.decode('utf-8')))
        publish({'HardwareVersion': hardwareVersion.decode('utf-8')}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)
        log.info('Software Version: {}'.format(softwareVersion.decode('utf-8')))
        publish({'SoftwareVersion': softwareVersion.decode('utf-8')}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)
        daysFloat = uptime / (60 * 60 * 24)
        days = math.trunc(daysFloat)
        hoursFloat = (daysFloat - days) * 24
        hours = math.trunc(hoursFloat)
        minutesFloat = (hoursFloat - hours) * 60
        minutes = math.trunc(minutesFloat)
        secondsFloat = (minutesFloat - minutes) * 60
        seconds = math.trunc(secondsFloat)
        log.info('Uptime: {}D{}H{}M{}S'.format(days, hours, minutes, seconds))
        publish({'Uptime': '{}D{}H{}M{}S'.format(days, hours, minutes, seconds)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)
        log.info('Power Up Times: {}'.format(powerUpTimes))
        publish({'Power Up Times: {}'.format(powerUpTimes)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=self.jkbms.tag)

    def processExtendedRecord(self, record):
        log.info('Processing extended record')
        del record[0:5]
        counter = record.pop(0)
        log.info('Record number: {}'.format(counter))


    def processField(self,record,fmt,bytes,name,unit):
        value = None
        if fmt == "Hex2Str":
            value = Hex2Str(record[0:bytes])
        elif fmt == "LittleHex2Short:r/1000":
            value =LittleHex2Short(record[0:bytes])/1000
        elif fmt == "LittleHex2Short:r/10":
            value =LittleHex2Short(record[0:bytes])/10
        elif fmt == "Hex2Int":
            value = Hex2Int(record[0:bytes])
        elif fmt == "LittleHex2UInt":
            value = LittleHex2UInt(record[0:bytes])
        elif fmt == "LittleHex2UInt:r/1000":
            value = LittleHex2UInt(record[0:bytes])/1000
        elif fmt == "LittleHex2Int:r/1000":
            value = LittleHex2Int(record[0:bytes])/1000
        elif fmt == "uptime":
            value = uptime(record[0:bytes])
        else:
            log.warn('Unknown format {}'.format(fmt))

        msgs = []
        topic = self.jkbms.tag+'/'+name+'/value'
        if(type(value) is int):
            log.info('{}: {:02d}{}'.format(name, value, unit))
            msgs.append( {'topic': topic, 'payload': '{:02d}'.format(value)} )
#            msgs.append(publish({'{:02d}'.format(value)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=topic))
        elif(type(value) is float):
            msgs.append( {'topic': topic, 'payload': '{:.3f}'.format(value)} )
            log.info('{}: {:.3f}{}'.format(name, value, unit))
#            msgs.append(publish({'{:.3f}'.format(value)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=topic))
        elif(type(value) is str):
            msgs.append( {'topic': topic, 'payload': '{}'.format(value)} )
            log.info('{}: {}{}'.format(name, value, unit))
#            msgs.append(publish({'{}'.format(value)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=topic))
        
        if(len(msgs)>0):
            topic = self.jkbms.tag+'/'+name+'/unit'
            msgs.append( {'topic': topic, 'payload': '{}'.format(unit)} )
#            msgs.append(publish({'{}'.format(unit)}, format=self.jkbms.format, broker=self.jkbms.mqttBroker, tag=topic))

        if(name[0]!='-'):
            return msgs
        else:
            return []


    def processCellDataRecord(self, record):
        log.info('Processing cell data record')
        log.info('Record length {}'.format(len(record)))
        msgs = []
        for fmt,bytes,name,unit in CellInfoResponseMapping:
            msgs += self.processField(record,fmt,bytes,name,unit)
            del record[0:bytes]

        print(msgs)
        publishToMqtt.multiple(msgs, hostname=self.jkbms.mqttBroker)



    def processRecord(self, record):
        print("processRecord")
        recordType = record[4]
        # counter = record[5]
        if recordType == INFO_RECORD:
            self.processInfoRecord(record)
        elif recordType == EXTENDED_RECORD:
            self.processExtendedRecord(record)
        elif recordType == CELL_DATA:
            self.processCellDataRecord(record)
        else:
            log.info('Unknown record type')

    def handleNotification(self, handle, data):
        # handle is the handle of the characteristic / descriptor that posted the notification
        # data is the data in this notification - may take multiple notifications to get all of a message
        log.debug("From handle: {:#04x} Got {} bytes of data".format(handle, len(data)))
        self.notificationData += bytearray(data)
        log.debug(f"Pre wipe to start {self.notificationData}")
        self.notificationData = self.wipe_to_start(self.notificationData)
        log.debug(f"Post wipe to start {self.notificationData}")
        # if not self._protocol.is_record_start(self.notificationData):
        #     log.debug(f"Not valid start of record - wiping data {self.notificationData}")
        #     self.notificationData = bytearray()
        if not self.is_record_correct_type(
            self.notificationData, self.record_type
        ):
            log.debug(
                f"Not expected type of record - wiping data {self.notificationData}"
            )
            self.notificationData = bytearray()
        if self.recordIsComplete(self.notificationData):
            self.jkbms.record = self.notificationData
            log.debug("record complete")
            self.notificationData = bytearray()
            self.processRecord(self.jkbms.record)

    def wipe_to_start(self, record):
        sor_loc = record.find(SOR)
        if sor_loc == -1:
            log.debug("SOR not found in record")
            return bytearray()
        return record[sor_loc:]
    
    def is_record_correct_type(self, record, type):
        if len(record) < len(SOR):
            return False
        if record[len(SOR)] == int(type):
            log.debug(f"Record is type {type}")
            return True
        return False


class jkBMS:
    """
    JK BMS Command Library
    - represents a JK BMS
    """

    def __str__(self):
        return 'JKBMS instance --- name: {}, model: {}, mac: {}, command: {}, tag: {}, format: {}, records: {}, maxConnectionAttempts: {}, mqttBroker: {}'.format(self.name, self.model, self.mac, self.command, self.tag, self.format, self.records, self.maxConnectionAttempts, self.mqttBroker)

    def __init__(self, name, model, mac, command, tag, format, records=1, maxConnectionAttempts=3, mqttBroker=None):
        '''
        '''
        self.name = name
        self.model = model
        self.mac = mac
        self.command = command
        self.tag = tag
        self.format = format
        try:
            self.records = int(records)
        except Exception:
            self.records = 1
        self.maxConnectionAttempts = maxConnectionAttempts
        self.mqttBroker = mqttBroker
        self.device = btle.Peripheral(None)
        log.debug('Config data - name: {}, model: {}, mac: {}, command: {}, tag: {}, format: {}'.format(self.name, self.model, self.mac, self.command, self.tag, self.format))
        log.debug('Additional config - records: {}, maxConnectionAttempts: {}, mqttBroker: {}'.format(self.records, self.maxConnectionAttempts, self.mqttBroker))
        print('jkBMS Logging level: {}'.format(log.level))

    def connect(self):
        # Intialise BLE device
        self.device = btle.Peripheral(None)
        self.delegate = jkBmsDelegate(self)
        self.device.withDelegate(self.delegate)
        # Connect to BLE Device
        connected = False
        attempts = 0
        log.info('Attempting to connect to {}'.format(self.name))
        while not connected:
            attempts += 1
            if attempts > self.maxConnectionAttempts:
                log.warning('Cannot connect to {} with mac {} - exceeded {} attempts'.format(self.name, self.mac, attempts - 1))
                return connected
            try:
                self.device.connect(self.mac)
                self.device.setMTU(330)
                connected = True
            except Exception:
                continue
        return connected
    

    def getBLEData(self):
        # Get the device name
        serviceId = self.device.getServiceByUUID(btle.AssignedNumbers.genericAccess)
        deviceName = serviceId.getCharacteristics(btle.AssignedNumbers.deviceName)[0]
        log.info('Connected to {}'.format(deviceName.read()))

        # Connect to the notify service
        serviceNotifyUuid = 'ffe0'
        serviceNotify = self.device.getServiceByUUID(serviceNotifyUuid)

        # Get the handles that we need to talk to
        # Read
        characteristicReadUuid = 'ffe1' # Grypho: Adopted to newer BMS systems
        characteristicRead = serviceNotify.getCharacteristics(characteristicReadUuid)[0]
        handleRead = characteristicRead.getHandle()
        log.info('Read characteristic: {}, handle {:x}'.format(characteristicRead, handleRead))

        # ## TODO sort below
        # Need to dynamically find this handle....
        log.info('Enable 0x0b handle', self.device.writeCharacteristic(0x0b, b'\x01\x00'))
        log.info('Enable read handle', self.device.writeCharacteristic(handleRead, b'\x01\x00'))
        self.delegate.record_type = 0x03
        log.info('Write getInfo to read handle', self.device.writeCharacteristic(handleRead, getInfo))
        secs = 0
        while True:
            if self.device.waitForNotifications(1.0):
                continue
            secs += 1
            if secs > 5:
                break

        self.delegate.record_type = 0x02
        log.info('Write getCellInfo to read handle', self.device.writeCharacteristic(handleRead, getCellInfo))
        loops = 0
        recordsToGrab = self.records
        log.info('Grabbing {} records (after inital response)'.format(recordsToGrab))

        while True:
            loops += 1
            if loops > recordsToGrab * 15 + 16:
                print('Got {} records'.format(recordsToGrab))
                break
            if self.device.waitForNotifications(1.0):
                continue

    def disconnect(self):
        log.info('Disconnecting...')
        self.device.disconnect()
