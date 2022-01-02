# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andrea Straforini
# This program is published under a GPLv3 (or later) license

# TODO: IT's ok gplv3?

# scapy.contrib.description =  Partial implementation of IEEE C37.118.2-2011
# scapy.contrib.status = loads


from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    FieldListField, IEEEFloatField, IntField, MultipleTypeField, \
    PacketListField, ShortEnumField, ShortField, SignedShortField, \
    StrField, StrFixedLenField, ThreeBytesField, XBitField, XByteField
from scapy.packet import Packet, bind_layers
import struct
from scapy.layers.inet import TCP, UDP


###############################################################################
# Copyright (C) Gennady Trafimenkov, 2011
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##########################################################################

CRC16_XMODEM_TABLE = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
]


def _crc16(data, crc, table):
    """Calculate CRC16 using the given table.
    `data`      - data for calculating CRC, must be bytes
    `crc`       - initial value
    `table`     - table for calculating CRC (list of 256 integers)
    Return calculated value of CRC
    """
    for byte in data:
        crc = ((crc << 8) & 0xff00) ^ table[((crc >> 8) & 0xff) ^ byte]
    return crc & 0xffff


def crc16xmodem(data, crc=0):
    """Calculate CRC-CCITT (XModem) variant of CRC16.
    `data`      - data for calculating CRC, must be bytes
    `crc`       - initial value
    Return calculated value of CRC
    """
    return _crc16(data, crc, CRC16_XMODEM_TABLE)


##################################################################
# END Licensed Code with Copyright (C) Gennady Trafimenkov, 2011 #
##################################################################

#############
# Enums #
#############


class CommonEnums():
    class SyncFieldEnums():
        VERSIONS = {
            0b0001: "Version 1",
            0b0010: "Version 2"
        }

        FRAME_TYPES = {
            0b000: "Data frame",
            0b001: "Header frame",
            0b010: "Cfg frame 1",
            0b011: "Cfg Frame 2",
            0b101: "Cfg frame 3",
            0b100: "Command frame"
        }

    class FracSecEnums():
        LEAP_SEC_PENDING = {
            0b1: "Leap second pending",
            0b0: "No leap second pending"
        }
        LEAP_SEC_OCCURED = {
            0b1: "Leap second occured",
            0b0: "No leap second occured"
        }
        LEAP_SEC_DIRECTION = {
            0b0: "Leap second add",
            0b1: "Leap second delete"
        }
        TQ_CODE = {
            0b0000: "Normal operation, clock locked to UTC traceable source",
            0b0001: "Time within 10^-9 s of UTC",
            0b0010: "Time within 10^-8 s of UTC",
            0b0011: "Time within 10^-7 s of UTC",
            0b0100: "Time within 10^-6 s of UTC",
            0b0101: "Time within 10^-5 s of UTC",
            0b0110: "Time within 10^-4 s of UTC",
            0b0111: "Time within 10^-3 s of UTC",
            0b1000: "Time within 10^-2 s of UTC",
            0b1001: "Time within 10^-1 s of UTC",
            0b1010: "Time within 1 s of UTC",
            0b1011: "Time within 10 s of UTC",
            0b1111: "Fault"
        }


class DataFrameEnums():
    class StatEnums():
        TRIGGER_REASON = {
            0b0000: "Manual",
            0b0001: "Magnitude low",
            0b0010: "Magnitude high",
            0b0011: "Phase angle diff",
            0b0100: "Frequency high or low",
            0b0101: "df/dt high",
            0b0110: "Reserved",
            0b0111: "Digital"
        }
        UNLOCKED_TIME = {
            0b00: "sync locked or unlocked < 10 s  (best quality)",
            0b01: "10s <= unlocked time < 100s ",
            0b10: "100 s < unlock tiem <= 1000s",
            0b11: "unlocked time > 1000 s"
        }
        PMU_TIME_QUALITY = {
            0b000: "Not used",
            0b001: "Estimated maximum time error < 100 ns",
            0b010: "Estimated maximum time error < 1 us",
            0b011: "Estimated maximum time error < 10 us",
            0b100: "Estimated maximum time error < 100 us",
            0b101: "Estimated maximum time error < 1 ms",
            0b110: "Estimated maximum time error < 10ms",
            0b111: "Estimated maximum time error > 10 ms \
or time error unknown",
        }
        DATA_MODIFIED = {
            0b1: "Data modified by post processing",
            0b0: "Data not modified by post processing"
        }
        CONFIGURATION_CHANGE = {
            0b0: "configuration will change",
            0b1: "configuration won't change"
        }
        PMU_TRIGGER = {
            0b0: "No pmu trigger",
            0b1: "Pmu triggere detected"
        }
        DATA_SORTING = {
            0b0: "sorting by timestamp",
            0b1: "Sorting by arrival"
        }
        PMU_SYNC = {
            0b0: "in sync with UTC treceable source",
            0b1: "Not in sync with UTC treceable source"
        }
        DATA_ERROR = {
            0b00: "Good measurement data, no errors",
            0b01: "PMU error, no information about data",
            0b10: "PMU in test mode or absent data tags have been inserted",
            0b11: "PMU error"}


class ConfigurationFrame1_2Enums():
    class FnomEnums():
        VALUE = {
            0b1: "Frequency 50Hz",
            0b0: "Frequency 60Hz"
        }

    class FormatEnums():
        TYPE = {
            0b0: "Rectangular",
            0b1: "Polar"
        }
        SIZE = {
            0b0: "16-bit Integer",
            0b1: "Floating point"
        }

    class PhUnitEnum():
        TYPE = {
            0: "voltage",
            1: "current"
        }

    class AnUnitEnum():
        TYPE = {
            0: "single point-on-wave",
            1: "rms of analog input",
            2: "peak of analog input",
            range(5, 65): "Reserved for future use definition",
            range(65, 256): "user definable"
        }


class CommandFrameEnums():
    CMD = {
        1: "Turn off transmission of data frames",
        2: "Turn on transmission of data frames",
        3: "Send HDR frame",
        4: "Send CFG-1 frame",
        5: "Send CFG-2 frame",
        6: "Send CFG-3 frame",
        7: "Reserved",
        8: "Extended frame",
        range(9, 256): "Reserved",
        range(266, 4096): "User defined",
        range(4096, 65536): "Reserved"
    }


##############
# Data Frame #
##############


class _PhasorValue(Packet):
    pass


class Phasor16BitRectangularFormatValue(_PhasorValue):
    name = "Phasor16BitIntegerValue"
    fields_desc = [
        SignedShortField("firstPart", 14635),
        SignedShortField("secondPart", 0)
    ]


class Phasor16BitPolarFormatValue(_PhasorValue):
    name = "Phasor16BitIntegerValue"
    fields_desc = [
        ShortField("firstPart", 14635),
        ShortField("secondPart", 0)
    ]


# both for polar and rectangular format
class Phasor32BitFloatValue(_PhasorValue):
    name = "Phasor32BitFloatValue"
    fields_desc = [
        IEEEFloatField("firstPart", 14635),
        IEEEFloatField("secondPart", 0)
    ]


class DataFrameEntry(Packet):
    name = "DataFrameEntry"
    fields_desc = [
        BitEnumField("statDataError", 0b00, 2,
                     DataFrameEnums.StatEnums.DATA_ERROR),
        BitEnumField("statPmuSync", 0b0, 1,
                     DataFrameEnums.StatEnums.PMU_SYNC),
        BitEnumField("statDataSorting", 0b0, 1,
                     DataFrameEnums.StatEnums.DATA_SORTING),
        BitEnumField("statTriggerDetected", 0b0, 1,
                     DataFrameEnums.StatEnums.PMU_TRIGGER),
        BitEnumField("statConfigurationChange", 0b0, 1,
                     DataFrameEnums.StatEnums.CONFIGURATION_CHANGE),
        BitEnumField("statDataModified", 0b0, 1,
                     DataFrameEnums.StatEnums.DATA_MODIFIED),
        BitEnumField("statTimeQuality", 0b000, 3,
                     DataFrameEnums.StatEnums.PMU_TIME_QUALITY),
        BitEnumField("statUnlockedTime", 0b00, 2,
                     DataFrameEnums.StatEnums.UNLOCKED_TIME),
        BitEnumField("statTriggerReason", 0b0000, 4,
                     DataFrameEnums.StatEnums.TRIGGER_REASON),
        PacketListField("phasorsList", [
            Phasor16BitRectangularFormatValue(firstPart=14635, secondPart=0),
            Phasor16BitRectangularFormatValue(
                        firstPart=-7318, secondPart=-12676),
            Phasor16BitRectangularFormatValue(
                firstPart=-7318, secondPart=12675),
            Phasor16BitRectangularFormatValue(firstPart=1092, secondPart=0),
        ], _PhasorValue
        ),
        MultipleTypeField(
            [
                (IEEEFloatField("freq", 2500.0), (
                    lambda pkt: True,
                    lambda pkt, val: isinstance(val, float)
                )
                ),
                (ShortField("freq", 2500), (
                    lambda pkt: True,
                    lambda pkt, val: isinstance(val, int)
                )
                )
            ], ShortField("freq", 2500),
        ),
        MultipleTypeField(
            [
                (IEEEFloatField("dfreq", 0.0), (
                    lambda pkt: True,
                    lambda pkt, val: isinstance(val, float)
                )
                ),
                (ShortField("dfreq", 0), (
                    lambda pkt: True,
                    lambda pkt, val: isinstance(val, int)
                )
                )
            ], ShortField("dfreq", 0),
        ),
        FieldListField(
            "analogList",
            [100.0, 1000.0, 10000.0],
            MultipleTypeField(
                [
                    (IEEEFloatField("analog", 100.0), (
                        lambda pkt: True,
                        lambda pkt, val: isinstance(val, float)
                    )),
                    (ShortField("analog", 100), (
                        lambda pkt: True,
                        lambda pkt, val: isinstance(val, int)
                    ))
                ], IEEEFloatField("analog", 100.0)
            )
        ),
        FieldListField("digitalList", [0b0011110000010010],
                       XBitField("digital", 0b0011110000010010, 16)),
    ]


class DataFrame(Packet):
    name = "DataFrame"
    fields_desc = [
        XByteField("syncHead", 0xaa),
        XBitField("syncReserved", 0b0, 1),
        BitEnumField("syncFrameType", 0b000, 3,
                     CommonEnums.SyncFieldEnums.FRAME_TYPES),
        BitEnumField("syncVersion", 0b0001, 4,
                     CommonEnums.SyncFieldEnums.VERSIONS),
        ShortField("framesize", None),
        ShortField("idcode", 7734),
        IntField("soc", 1149580800),
        XBitField("fracsecReserved", 0b0, 1),
        BitEnumField("fracsecLeapSecDirection", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_DIRECTION),
        BitEnumField("fracsecLeapSecOccured", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_OCCURED),
        BitEnumField("fracsecLeapSecPending", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_PENDING),
        BitEnumField("fracsecTimeQuality", 0b0000, 4,
                     CommonEnums.FracSecEnums.TQ_CODE),
        ThreeBytesField("fracsecValue", 0x0041b1),
        PacketListField("dataFrameEntriesList", [
            DataFrameEntry(),
        ], DataFrameEntry),
        ShortField("chk", None)
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.framesize is None:
            pkt = pkt[: 2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.chk is None:
            pkt = pkt[: -2] + struct.pack("!H", crc16xmodem(pkt[:-2], 0xffff))
        return pkt + pay


###############
# CFG Frame 2 #
###############

class PhUnitField(Packet):
    name = "PhUnitField"
    fields_desc = [
        ByteEnumField(
            "type", 0, ConfigurationFrame1_2Enums.PhUnitEnum.TYPE),
        BitField("scaling", 0x0df847, 24)
    ]


class AnUnitField(Packet):
    name = "AnUnitField"
    fields_desc = [
        ByteEnumField(
            "type", 0, ConfigurationFrame1_2Enums.AnUnitEnum.TYPE),
        BitField("scaling", 1, 24)
    ]


class DigUnitField(Packet):
    name = "DigUnitField"
    fields_desc = [
        XBitField("normalStatus", 0, 16),
        XBitField("validInputs", 0xffff, 16)
    ]


class ConfigurationFrame2Entry(Packet):
    name = "ConfigurationFrame2Entry"
    fields_desc = [
        StrFixedLenField("stn", "Station A       ", 16),
        ShortField("idCode", 7734),
        XBitField("formatUnused", 0, 12),
        BitEnumField("formatFreqSize", 0b0, 1,
                     ConfigurationFrame1_2Enums.FormatEnums.SIZE),
        BitEnumField("formatAnalogsSize", 0b1, 1,
                     ConfigurationFrame1_2Enums.FormatEnums.SIZE),
        BitEnumField("formatPhasorsDataSize", 0b0, 1,
                     ConfigurationFrame1_2Enums.FormatEnums.SIZE),
        BitEnumField("formatPhasorsType", 0b0, 1,
                     ConfigurationFrame1_2Enums.FormatEnums.TYPE),
        ShortField("phnmr", 4),
        ShortField("annmr", 3),
        ShortField("dgnmr", 1),
        FieldListField("chnamList", [
            "VA              ",
            "VB              ",
            "VC              ",
            "I1              ",
            "ANALOG1         ",
            "ANALOG2         ",
            "ANALOG3         ",
            "BREAKER 1 STATUS",
            "BREAKER 2 STATUS",
            "BREAKER 3 STATUS",
            "BREAKER 4 STATUS",
            "BREAKER 5 STATUS",
            "BREAKER 6 STATUS",
            "BREAKER 7 STATUS",
            "BREAKER 8 STATUS",
            "BREAKER 9 STATUS",
            "BREAKER A STATUS",
            "BREAKER B STATUS",
            "BREAKER C STATUS",
            "BREAKER D STATUS",
            "BREAKER E STATUS",
            "BREAKER F STATUS",
            "BREAKER G STATUS",

        ], StrFixedLenField("chanam", "", 16)),
        PacketListField("phUnitList", [
            PhUnitField(),
            PhUnitField(),
            PhUnitField(),
            PhUnitField(type=1, scaling=45776),
        ],
            PhUnitField),
        PacketListField(
            "anUnitList", [
                AnUnitField(),
                AnUnitField(type=1),
                AnUnitField(type=2)
            ],
            AnUnitField),
        PacketListField("digUnitList", [
            DigUnitField()
        ], DigUnitField),
        BitField("fnomReserved", 0, 15),
        BitEnumField("fnomHead", 0b0, 1,
                     ConfigurationFrame1_2Enums.FnomEnums.VALUE),
        ShortField("cfgCnt", 22)
    ]


class ConfigurationFrame2(Packet):
    name = "ConfigurationFrame2"
    fields_desc = [
        XByteField("syncHead", 0xaa),
        XBitField("syncReserved", 0b0, 1),
        BitEnumField("syncFrameType", 0b011, 3,
                     CommonEnums.SyncFieldEnums.FRAME_TYPES),
        BitEnumField("syncVersion", 0b0001, 4,
                     CommonEnums.SyncFieldEnums.VERSIONS),
        ShortField("framesize", None),
        ShortField("idcode", 7734),
        IntField("soc", 1149577200),
        XBitField("fracsecReserved", 0b0, 1),
        BitEnumField("fracsecLeapSecDirection", 0b1, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_DIRECTION),
        BitEnumField("fracsecLeapSecOccured", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_OCCURED),
        BitEnumField("fracsecLeapSecPending", 0b1, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_PENDING),
        BitEnumField("fracsecTimeQuality", 0b0110, 4,
                     CommonEnums.FracSecEnums.TQ_CODE),
        ThreeBytesField("fracsecValue", 0x071098),
        ByteField("timeBaseFlags", 0x00),
        ThreeBytesField("timeBaseValue", 0x0f4240),
        ShortField("numPmu", 1),
        PacketListField("configurationFrame2ListEntries",
                        [ConfigurationFrame2Entry(), ],
                        ConfigurationFrame2Entry),
        SignedShortField("dataRate", 30),
        ShortField("chk", None)
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.framesize is None:
            pkt = pkt[: 2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.chk is None:
            pkt = pkt[: -2] + struct.pack("!H", crc16xmodem(pkt[:-2], 0xffff))
        return pkt + pay


###############
# CFG Frame 1 #
###############

# TODO::
# class ConfigurationFrame1(Packet):
#    name = "ConfigurationFrame1"


###############
# CFG Frame 3 #
###############

# TODO::
# class ConfigurationFrame3(Packet):
#    name = "ConfigurationFrame3"


#################
# Command Frame #
#################


class CommandFrame(Packet):
    name = "CommandFrame"
    fields_desc = [
        XByteField("syncHead", 0xaa),
        XBitField("syncReserved", 0b0, 1),
        BitEnumField("syncFrameType", 0b100, 3,
                     CommonEnums.SyncFieldEnums.FRAME_TYPES),
        BitEnumField("syncVersion", 0b0001, 4,
                     CommonEnums.SyncFieldEnums.VERSIONS),
        ShortField("framesize", None),
        ShortField("idcode", 7734),
        IntField("soc", 1149591600),
        XBitField("fracsecReserved", 0b0, 1),
        BitEnumField("fracsecLeapSecDirection", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_DIRECTION),
        BitEnumField("fracsecLeapSecOccured", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_OCCURED),
        BitEnumField("fracsecLeapSecPending", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_PENDING),
        BitEnumField("fracsecTimeQuality", 0b1111, 4,
                     CommonEnums.FracSecEnums.TQ_CODE),
        ThreeBytesField("fracsecValue", 0x0bbfd0),
        ShortEnumField("cmd", 2, CommandFrameEnums.CMD),
        FieldListField("extFrame", [], ByteField("extFrameByte", 0)),
        ShortField("chk", None)
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.framesize is None:
            pkt = pkt[: 2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.chk is None:
            pkt = pkt[: -2] + struct.pack("!H", crc16xmodem(pkt[:-2], 0xffff))
        return pkt + pay


################
# Header Frame #
################


class HeaderFrame(Packet):
    name = "HeaderFrame"
    fields_desc = [
        XByteField("syncHead", 0xaa),
        XBitField("syncReserved", 0b0, 1),
        BitEnumField("syncFrameType", 0b001, 3,
                     CommonEnums.SyncFieldEnums.FRAME_TYPES),
        BitEnumField("syncVersion", 0b0001, 4,
                     CommonEnums.SyncFieldEnums.VERSIONS),
        ShortField("framesize", None),
        ShortField("idcode", 7734),
        IntField("soc", 1149577200),
        XBitField("fracsecReserved", 0b0, 1),
        BitEnumField("fracsecLeapSecDirection", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_DIRECTION),
        BitEnumField("fracsecLeapSecOccured", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_OCCURED),
        BitEnumField("fracsecLeapSecPending", 0b0, 1,
                     CommonEnums.FracSecEnums.LEAP_SEC_PENDING),
        BitEnumField("fracsecTimeQuality", 0b0000, 4,
                     CommonEnums.FracSecEnums.TQ_CODE),
        ThreeBytesField("fracsecValue", 0x071098),
        StrField("data", "HI!"),
        ShortField("chk", None)
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.framesize is None:
            pkt = pkt[: 2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.chk is None:
            pkt = pkt[: -2] + struct.pack("!H", crc16xmodem(pkt[:-2], 0xffff))
        return pkt + pay


bind_layers(TCP, HeaderFrame, dport=4712, sport=4712)
bind_layers(TCP, CommandFrame, dport=4712, sport=4712)
bind_layers(TCP, ConfigurationFrame2, dport=4712, sport=4712)
bind_layers(TCP, DataFrame, dport=4712, sport=4712)
# bind_layers(TCP, ConfigurationFrame1, dport=4712, sport=4712)
# bind_layers(TCP, ConfigurationFrame3, dport=4712, sport=4712)


bind_layers(UDP, HeaderFrame, dport=4713, sport=4713)
bind_layers(UDP, CommandFrame, dport=4713, sport=4713)
bind_layers(UDP, ConfigurationFrame2, dport=4713, sport=4713)
bind_layers(UDP, DataFrame, dport=4713, sport=4713)
# bind_layers(UDP, ConfigurationFrame1, dport=4713, sport=4713)
# bind_layers(UDP, ConfigurationFrame3, dport=4713, sport=4713)
