#!/usr/bin/env python3
from bluepy import btle
import logging
import systemd.daemon
import time

from .jkbms_mapping import CellInfoResponseMapping, InfoResponseMapping
from .publishMqtt import publishMqtt as publish
import paho.mqtt.publish as publishToMqtt

from .jkbmsdecode import DATA_ASCII, DecodeFormat, Hex2Ascii, crc8, Hex2Str, uptime

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



log = logging.getLogger('JKBMS-BT')

SOR = bytes.fromhex("55aaeb90")

class jkBmsDelegate(btle.DefaultDelegate):
    '''
    BLE delegate to deal with notifications (information) from the JKBMS device
    '''
    # JKBMS hat bei getCellInfo 0x02 und bei getInfo 0x03
    def __init__(self, jkbms):
        btle.DefaultDelegate.__init__(self)
        # extra initialisation here
        self.jkbms = jkbms
        print('Delegate {}'.format(str(jkbms)))
        self.notificationData = bytearray()
        self.record_type = None
        self.record_counter = 0
        self.rx_counter = 0


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
            #log.debug (crc, calcCrc, "len ", len(self.notificationData))
            #log.debug(hexdump(self.notificationData))
            if crc == calcCrc:
                log.debug("Record CRC is valid")
                return True
        return False


    def processExtendedRecord(self, record):
        log.info('Processing extended record')
        del record[0:5]
        counter = record.pop(0)
        log.info('Record number: {}'.format(counter))


    def convertField(self,record,fmt,bytes,topic,name,unit):
        value = None
        if fmt == "Hex2Str":
            value = Hex2Str(record[0:bytes])
        elif fmt == "discard":
            return []
        elif fmt == "uptime":
            value = uptime(record[0:bytes])
        elif fmt == DATA_ASCII:
            value = Hex2Ascii(record[0:bytes])
        else:
            fmt_split = fmt.split(":")
            value = DecodeFormat(fmt_split[0], record[0:bytes]);
            if len(fmt_split)>1 and fmt_split[1] == "r/1000":
                value /= 1000
            if len(fmt_split)>1 and fmt_split[1] == "r/10":
                value /= 10

        return value


    def sendField(self,value,topic,name,unit):
        msgs = []
        topic = self.jkbms.tag+'/'+topic+'/'+name
        if (unit):
            topic+='_'+unit

        if(type(value) is int):
            log.info('{}: {:2d}{}'.format(name, value, unit))
            msgs.append( {'topic': topic, 'payload': '{:d}'.format(value)} )
        elif(type(value) is float):
            msgs.append( {'topic': topic, 'payload': '{:.3f}'.format(value)} )
            log.info('{}: {:.3f}{}'.format(name, value, unit))
        elif(type(value) is str):
            msgs.append( {'topic': topic, 'payload': '{}'.format(value)} )
            log.info('{}: {}{}'.format(name, value, unit))
        
        if(name[0]!='-'):
            return msgs
        else:
            return []
        
    def processCellDataRecord(self, record):
        log.info('Processing cell data record')
        log.info('Record length {}'.format(len(record)))
        self.rx_counter += 1
        fields = {}
        # *opts is a catchall for all remaining arguments
        # opts is an empty list if there is no 5th argument and evaluate to false.

        for fmt,bytes,name,unit,*opts in CellInfoResponseMapping:
            mqttFrequency = opts[0] if opts else 1
            if (self.record_counter % mqttFrequency == 0) and (name[0]!='-'):
#                print('* {}'.format(name))
                fields[name] = self.convertField(record,fmt,bytes,"CellData",name,unit)
#            else:
#                print('_ {}'.format(name))
            del record[0:bytes]

        # Field BatteryPower uses only absolute values. Using BatteryCurrent to provide power direction
        if(fields["BatteryCurrent"] < 0):
            fields["BatteryPower"] = -fields["BatteryPower"]


        msgs = []
        for fmt,bytes,name,unit,*opts in CellInfoResponseMapping:
            mqttFrequency = opts[0] if opts else 1
            if (self.record_counter % mqttFrequency == 0) and (name[0]!='-'):
                msgs += self.sendField(fields[name],"CellData",name,unit)


        if self.rx_counter == self.jkbms.recordDivider:
            self.rx_counter = 0
            self.record_counter += 1
            log.debug(msgs)
            publishToMqtt.multiple(msgs, hostname=self.jkbms.mqttBroker)
            log.info("MQTT sent")

    def processInfoRecord(self, record):
        log.info('Processing cell data record')
        log.info('Record length {}'.format(len(record)))
        msgs = []
        for fmt,bytes,name,unit in InfoResponseMapping:
            value = self.convertField(record,fmt,bytes,"CellData",name,unit)
            msgs += self.sendField(value,"CellData",name,unit)
            del record[0:bytes]

        log.debug(msgs)
        publishToMqtt.multiple(msgs, hostname=self.jkbms.mqttBroker)


    def processRecord(self, record):
        recordType = record[4]
        if self.jkbms.isDaemon:
            systemd.daemon.notify('WATCHDOG=1')

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

    def __init__(self, name, model, mac, command, tag, format, records=1, recordDivider=1, maxConnectionAttempts=3, mqttBroker=None, daemon=False):
        '''
        '''
        self.name = name
        self.model = model
        self.mac = mac
        self.command = command
        self.tag = tag
        self.format = format
        self.recordDivider = recordDivider
        self.isDaemon = daemon
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
        print('daemonize: {}'.format(self.isDaemon))

    def connect(self):
        if self.isDaemon:
            time.sleep(10)
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

        if self.isDaemon:
            # Tell systemd that our service is ready
            systemd.daemon.notify('READY=1')


        log.info('Grabbing {} (every {}th) records (after inital response)'.format(recordsToGrab, self.recordDivider))

        while True:
            loops += 1
            if self.delegate.record_counter >= recordsToGrab and not self.isDaemon:
                log.info('Got {} records'.format(recordsToGrab))
                break
            if self.device.waitForNotifications(1.0):
                continue

    def disconnect(self):
        log.info('Disconnecting...')
        self.device.disconnect()
        if self.isDaemon:
            time.sleep(10)
            
