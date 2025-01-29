
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
http://github.com/riptideio/pymodbus 2.3.0
Diagnostic record read/write
Currently not all implemented
'''
import struct
import modbus_tcp_b 
from utils_b import *
from libraries.compat import byte2int, int2byte

#---------------------------------------------------------------------------#
# TODO Make these only work on serial
#---------------------------------------------------------------------------#
class ReadExceptionStatusRequest():
    '''
    This function code is used to read the contents of eight Exception Status
    outputs in a remote device.  The function provides a simple method for
    accessing this information, because the Exception Output references are
    known (no output reference is needed in the function).
    '''
    function_code = 0x07
    _rtu_frame_size = 4

    def __init__(self, **kwargs):
        ''' Initializes a new instance
        '''
        #ModbusRequest.__init__(self, **kwargs)

    def encode(self):
        ''' Encodes the message
        '''
        return b''

    def decode(self, data):
        ''' Decodes data part of the message.

        :param data: The incoming data
        '''
        pass

    def execute(self, context=None):
        ''' Run a read exeception status request against the store

        :returns: The populated response
        '''
        status = _MCB.Counter.summary()
        return ReadExceptionStatusResponse(status)

    def __str__(self):
        ''' Builds a representation of the request

        :returns: The string representation of the request
        '''
        return "ReadExceptionStatusRequest(%d)" % (self.function_code)


class ReadExceptionStatusResponse():
    '''
    The normal response contains the status of the eight Exception Status
    outputs. The outputs are packed into one data byte, with one bit
    per output. The status of the lowest output reference is contained
    in the least significant bit of the byte.  The contents of the eight
    Exception Status outputs are device specific.
    '''
    function_code = 0x07
    _rtu_frame_size = 5

    def __init__(self, status=0x00, **kwargs):
        ''' Initializes a new instance

        :param status: The status response to report
        '''
        #ModbusResponse.__init__(self, **kwargs)
        self.status = status

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        return struct.pack('>B', self.status)

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        self.status = byte2int(data[0])
        arguments=(self.status)
        return arguments

    def __str__(self):
        ''' Builds a representation of the response

        :returns: The string representation of the response
        '''
        arguments = (self.function_code, self.status)
        return "ReadExceptionStatusResponse(%d, %s)" % arguments

# Encapsulate interface transport 43, 14
# CANopen general reference 43, 13


#---------------------------------------------------------------------------#
# TODO Make these only work on serial
#---------------------------------------------------------------------------#
class GetCommEventCounterRequest():
    '''
    This function code is used to get a status word and an event count from
    the remote device's communication event counter.

    By fetching the current count before and after a series of messages, a
    client can determine whether the messages were handled normally by the
    remote device.

    The device's event counter is incremented once  for each successful
    message completion. It is not incremented for exception responses,
    poll commands, or fetch event counter commands.

    The event counter can be reset by means of the Diagnostics function
    (code 08), with a subfunction of Restart Communications Option
    (code 00 01) or Clear Counters and Diagnostic Register (code 00 0A).
    '''
    function_code = 0x0b
    _rtu_frame_size = 4

    def __init__(self, **kwargs):
        ''' Initializes a new instance
        '''
        #ModbusRequest.__init__(self, **kwargs)

    def encode(self):
        ''' Encodes the message
        '''
        return b''

    def decode(self, data):
        ''' Decodes data part of the message.

        :param data: The incoming data
        '''
        pass

    def execute(self, context=None):
        ''' Run a read exeception status request against the store

        :returns: The populated response
        '''
        status = _MCB.Counter.Event
        return GetCommEventCounterResponse(status)

    def __str__(self):
        ''' Builds a representation of the request

        :returns: The string representation of the request
        '''
        return "GetCommEventCounterRequest(%d)" % (self.function_code)


class GetCommEventCounterResponse():
    '''
    The normal response contains a two-byte status word, and a two-byte
    event count. The status word will be all ones (FF FF hex) if a
    previously-issued program command is still being processed by the
    remote device (a busy condition exists). Otherwise, the status word
    will be all zeros.
    '''
    function_code = 0x0b
    _rtu_frame_size = 8

    def __init__(self, count=0x0000, **kwargs):
        ''' Initializes a new instance

        :param count: The current event counter value
        '''
        #ModbusResponse.__init__(self, **kwargs)
        self.count = count
        self.status = True  # this means we are ready, not waiting

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        if self.status: ready = ModbusStatus.Ready
        else: ready = ModbusStatus.Waiting
        return struct.pack('>HH', ready, self.count)

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        #ready, self.count = struct.unpack('>HH', data)
        #self.status = (ready == ModbusStatus.Ready)
        self.status, self.count = struct.unpack('>HH', data)
        arguments = (self.status,self.count) 
        return arguments 

    def __str__(self):
        ''' Builds a representation of the response

        :returns: The string representation of the response
        '''
        arguments = (self.function_code, self.count, self.status)
        return "GetCommEventCounterResponse(%d, %d, %d)" % arguments


#---------------------------------------------------------------------------#
# TODO Make these only work on serial
#---------------------------------------------------------------------------#
class GetCommEventLogRequest():
    '''
    This function code is used to get a status word, event count, message
    count, and a field of event bytes from the remote device.

    The status word and event counts are identical  to that returned by
    the Get Communications Event Counter function (11, 0B hex).

    The message counter contains the quantity of  messages processed by the
    remote device since its last restart, clear counters operation, or
    power-up.  This count is identical to that returned by the Diagnostic
    function (code 08), sub-function Return Bus Message Count (code 11,
    0B hex).

    The event bytes field contains 0-64 bytes, with each byte corresponding
    to the status of one MODBUS send or receive operation for the remote
    device.  The remote device enters the events into the field in
    chronological order.  Byte 0 is the most recent event. Each new byte
    flushes the oldest byte from the field.
    '''
    function_code = 0x0c
    _rtu_frame_size = 4

    def __init__(self, **kwargs):
        ''' Initializes a new instance
        '''
        #ModbusRequest.__init__(self, **kwargs)

    def encode(self):
        ''' Encodes the message
        '''
        return b''

    def decode(self, data):
        ''' Decodes data part of the message.

        :param data: The incoming data
        '''
        pass

    def execute(self, context=None):
        ''' Run a read exeception status request against the store

        :returns: The populated response
        '''
        results = {
            'status'        : True,
            'message_count' : _MCB.Counter.BusMessage,
            'event_count'   : _MCB.Counter.Event,
            'events'        : _MCB.getEvents(),
        }
        return GetCommEventLogResponse(**results)

    def __str__(self):
        ''' Builds a representation of the request

        :returns: The string representation of the request
        '''
        return "GetCommEventLogRequest(%d)" % self.function_code


class GetCommEventLogResponse():
    '''
    The normal response contains a two-byte status word field,
    a two-byte event count field, a two-byte message count field,
    and a field containing 0-64 bytes of events. A byte count
    field defines the total length of the data in these four field
    '''
    function_code = 0x0c
    _rtu_byte_count_pos = 2

    def __init__(self, **kwargs):
        ''' Initializes a new instance

        :param status: The status response to report
        :param message_count: The current message count
        :param event_count: The current event count
        :param events: The collection of events to send
        '''
        #ModbusResponse.__init__(self, **kwargs)
        self.status = kwargs.get('status', True)
        self.message_count = kwargs.get('message_count', 0)
        self.event_count = kwargs.get('event_count', 0)
        self.events = kwargs.get('events', [])

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        if self.status: ready = ModbusStatus.Ready
        else: ready = ModbusStatus.Waiting
        packet  = struct.pack('>B', 6 + len(self.events))
        packet += struct.pack('>H', ready)
        packet += struct.pack('>HH', self.event_count, self.message_count)
        packet += b''.join(struct.pack('>B', e) for e in self.events)
        return packet

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        length = byte2int(data[0])
        status = struct.unpack('>H', data[1:3])[0]
        #self.status = (status == ModbusStatus.Ready), fix for fuzzer
        self.event_count = struct.unpack('>H', data[3:5])[0]
        self.message_count = struct.unpack('>H', data[5:7])[0]

        self.events = []
        for e in range(7, length + 1):
            self.events.append(byte2int(data[e]))
        #custom add
        arguments=(self.status, self.message_count, self.event_count)     
        return arguments   
        

    def __str__(self):
        ''' Builds a representation of the response

        :returns: The string representation of the response
        '''
        arguments = (self.function_code, self.status, self.message_count, self.event_count)
        return "GetCommEventLogResponse(%d, %d, %d, %d)" % arguments


#---------------------------------------------------------------------------#
# TODO Make these only work on serial
#---------------------------------------------------------------------------#
class ReportSlaveIdRequest():
    '''
    This function code is used to read the description of the type, the
    current status, and other information specific to a remote device.
    '''
    function_code = 0x11
    _rtu_frame_size = 4

    def __init__(self, **kwargs):
        ''' Initializes a new instance
        '''
        #ModbusRequest.__init__(self, **kwargs),fix for fuzzer

    def encode(self):
        ''' Encodes the message
        '''
        return b''

    def decode(self, data):
        ''' Decodes data part of the message.

        :param data: The incoming data
        '''
        pass

    def execute(self, context=None):
        ''' Run a read exeception status request against the store

        :returns: The populated response
        '''
        information = DeviceInformationFactory.get(_MCB)
        identifier = "-".join(information.values()).encode()
        identifier = identifier or b'Pymodbus'
        return ReportSlaveIdResponse(identifier)

    def __str__(self):
        ''' Builds a representation of the request

        :returns: The string representation of the request
        '''
        return "ResportSlaveIdRequest(%d)" % self.function_code


class ReportSlaveIdResponse():
    '''
    The format of a normal response is shown in the following example.
    The data contents are specific to each type of device.
    '''
    function_code = 0x11
    _rtu_byte_count_pos = 2

    def __init__(self, identifier=b'\x00', status=True, **kwargs):
        ''' Initializes a new instance

        :param identifier: The identifier of the slave
        :param status: The status response to report
        '''
        #ModbusResponse.__init__(self, **kwargs),fix for fuzzer
        self.identifier = identifier
        self.status = status
        self.byte_count = None

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        if self.status:
            status = ModbusStatus.SlaveOn
        else:
            status = ModbusStatus.SlaveOff
        length  = len(self.identifier) + 1
        packet  = int2byte(length)
        packet += self.identifier  # we assume it is already encoded
        packet += int2byte(status)
        return packet

    def decode(self, data):
        ''' Decodes a the response

        Since the identifier is device dependent, we just return the
        raw value that a user can decode to whatever it should be.

        :param data: The packet data to decode
        '''
        self.byte_count = byte2int(data[0])
        self.identifier = data[1:self.byte_count + 1]
        status = byte2int(data[-1])
        #self.status = status == ModbusStatus.SlaveOn
        self.status = status 
        arguments = (self.identifier, self.status)
        return arguments

    def __str__(self):
        ''' Builds a representation of the response

        :returns: The string representation of the response
        '''
        arguments = (self.function_code, self.identifier, self.status)
        return "ResportSlaveIdResponse(%s, %s, %s)" % arguments

#---------------------------------------------------------------------------#
# TODO Make these only work on serial
#---------------------------------------------------------------------------#
# report device identification 43, 14

#---------------------------------------------------------------------------#
# Exported symbols
#---------------------------------------------------------------------------#
__all__ = [
    "ReadExceptionStatusRequest", "ReadExceptionStatusResponse",
    "GetCommEventCounterRequest", "GetCommEventCounterResponse",
    "GetCommEventLogRequest", "GetCommEventLogResponse",
    "ReportSlaveIdRequest", "ReportSlaveIdResponse",
]
