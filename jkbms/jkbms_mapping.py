from .jkbmsdecode import DATA_ASCII, DATA_INT16_DIV10, DATA_INT32_DIV1000, DATA_UINT16_DIV1000, DATA_UINT32, DATA_UINT32_DIV1000, DATA_UINT8, EVERY5TH,EVERY10TH, EVERY60TH


InfoResponseMapping = [
    ["Hex2Str", 4, "-Header", ""],
    ["Hex2Str", 1, "-Record Type", ""],
    [DATA_UINT8, 1, "RecordCounter", ""],
    [DATA_ASCII, 16, "DeviceModel", ""],
    [DATA_ASCII, 8, "HardwareVersion", ""],
    [DATA_ASCII, 8, "SoftwareVersion", ""],
    ["uptime", 4, "Uptime", "s"],
    [DATA_UINT32, 4, "PowerOnTimes", ""],
    [DATA_ASCII, 16, "DeviceName", ""],
    [DATA_ASCII, 16, "-DevicePasscode", ""],
    [DATA_ASCII, 8, "ManufacturingDate", ""],
    [DATA_ASCII, 11, "SerialNumber", ""],
    [DATA_ASCII, 5, "-Passcode", ""],
    [DATA_ASCII, 16, "-UserData", ""],
    [DATA_ASCII, 16, "-Setup Passcode", ""],
    ["discard", 672, "unknown", ""],
]

CellInfoResponseMapping = [
    ("Hex2Str", 4, "-Header", ""),
    ("Hex2Str", 1, "-Record_Type", ""),
    (DATA_UINT8, 1, "Record_Counter", "", EVERY60TH),
    (DATA_UINT16_DIV1000, 2, "VoltageCell01", "V", EVERY5TH),
    (DATA_UINT16_DIV1000, 2, "VoltageCell02", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell03", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell04", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell05", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell06", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell07", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell08", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell09", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell10", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell11", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell12", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell13", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell14", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell15", "V"),
    (DATA_UINT16_DIV1000, 2, "VoltageCell16", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell17", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell18", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell19", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell20", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell21", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell22", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell23", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell24", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell25", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell26", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell27", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell28", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell29", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell30", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell31", "V"),
    (DATA_UINT16_DIV1000, 2, "-VoltageCell32", "V"),
    ("Hex2Str", 4, "EnabledCellsBitmask", "", EVERY60TH), #0xFF000000 => 8 cells, 0xFF010000 => 9 cells, ..., 0xFFFF0000 => 16cells
    (DATA_UINT16_DIV1000, 2, "AverageCellVoltage", "V"),
    (DATA_UINT16_DIV1000, 2, "DeltaCellVoltage", "V"),
    (DATA_UINT16_DIV1000, 2, "CurrentBalancer", "A"),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell01", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell02", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell03", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell04", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell05", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell06", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell07", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell08", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell09", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell10", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell11", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell12", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell13", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell14", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell15", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "ResistanceCell16", "Ohm",EVERY10TH),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell17", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell18", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell19", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell20", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell21", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell22", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell23", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell24", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell25", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell26", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell27", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell28", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell29", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell30", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell31", "Ohm"),
    (DATA_UINT16_DIV1000, 2, "-ResistanceCell32", "Ohm"),
    ("Hex2Str", 6, "-discard2", ""),
    (DATA_UINT32_DIV1000, 4, "BatteryVoltage", "V"),
    (DATA_UINT32_DIV1000, 4, "BatteryPower", "W"),
    (DATA_INT32_DIV1000, 4, "BalanceCurrent", "A"),  # signed int32
    # ("discard", 8, "discard3", ""),
    (DATA_INT16_DIV10, 2, "BatteryT1", "C", EVERY60TH),
    (DATA_INT16_DIV10, 2, "BatteryT2", "C", EVERY60TH),
    (DATA_INT16_DIV10, 2, "MOSTemp", "C", EVERY60TH),
    ("Hex2Str", 2, "-Unknown3", ""), #0x0001 charge overtemp, 0x0002 charge undertemp. 0x0008 cell undervoltage, 0x0400 cell count error, 0x0800 current sensor anomaly, 0x1000 cell overvoltage
    ("discard", 2, "-discard4", ""),  # discard4
    ("discard", 1, "-discard4_1", ""),  # added
    (DATA_UINT8, 1, "PercentRemain", "Pct", EVERY5TH),
    (DATA_UINT32_DIV1000, 4, "CapacityRemain", "Ah", EVERY5TH),  # Unknown6+7
    (DATA_UINT32_DIV1000, 4, "NominalCapacity", "Ah", EVERY60TH),  # Unknown8+9
    (DATA_UINT32, 4, "CycleCount", "", EVERY60TH),
    # ("discard", 2, "Unknown10", ""),
    # ("discard", 2, "Unknown11", ""),
    (DATA_UINT32_DIV1000, 4, "CycleCapacity", "Ah", EVERY60TH),  # Unknown10+11
    ("discard", 2, "-Unknown12", ""),
    ("discard", 2, "-Unknown13", ""),
    ("uptime", 3, "Uptime", "s"),
    ("discard", 2, "-Unknown15", ""),
    ("discard", 2, "-Unknown16", ""),
    ("discard", 2, "-Unknown17", ""),
    ("discard", 12, "-discard6", ""),
    ("discard", 2, "-Unknown18", ""),
    ("discard", 2, "-Unknown19", ""),
    ("discard", 2, "-Unknown20", ""),
    (DATA_UINT16_DIV1000, 2, "CurrentCharge", "A"),  # Unknown21
    (DATA_UINT16_DIV1000, 2, "CurrentDischarge", "A"),  # Unknown22
    ("discard", 2, "-Unknown23", ""),
    ("discard", 2, "-Unknown24", ""),
    ("discard", 2, "-Unknown25", ""),
    ("discard", 2, "-Unknown26", ""),
    ("discard", 2, "-Unknown27", ""),
    ("discard", 2, "-Unknown28", ""),
    ("discard", 2, "-Unknown29", ""),
    ("discard", 4, "-Unknown30", ""),
    ("discard", 4, "-Unknown31", ""),
    ("discard", 4, "-Unknown32", ""),
    ("discard", 4, "-Unknown33", ""),
    ("discard", 4, "-Unknown34", ""),
    ("discard", 4, "-Unknown35", ""),
    ("discard", 4, "-Unknown36", ""),
    ("discard", 4, "-Unknown37", ""),
    ("discard", 4, "-Unknown38", ""),
    ("discard", 4, "-Unknown39", ""),
    ("discard", 4, "-Unknown40", ""),
    ("discard", 4, "-Unknown41", ""),
    ("discard", 45, "-UnknownXX", ""),
]