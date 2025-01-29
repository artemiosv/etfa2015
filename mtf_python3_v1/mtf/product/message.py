#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
http://github.com/riptideio/pymodbus 2.3.0
File Record Read/Write Messages
-------------------------------
'''
import struct
import modbus_tcp_b
import sys 
from utils_b import *

class MoreData():
    ''' Represents the more follows condition

    .. attribute:: Nothing

       This indiates that no more objects are going to be returned.

    .. attribute:: KeepReading

       This indicates that there are more objects to be returned.
    '''
    Nothing     = 0x00
    KeepReading = 0xFF

#---------------------------------------------------------------------------#
# File Record Types
#---------------------------------------------------------------------------#
class FileRecord(object):
    ''' Represents a file record and its relevant data.
    '''

    def __init__(self, **kwargs):
        ''' Initializes a new instance

        :params reference_type: Defaults to 0x06 (must be)
        :params file_number: Indicates which file number we are reading
        :params record_number: Indicates which record in the file
        :params record_data: The actual data of the record
        :params record_length: The length in registers of the record
        :params response_length: The length in bytes of the record
        '''
        self.reference_type  = kwargs.get('reference_type', 0x06)
        self.file_number     = kwargs.get('file_number', 0x00)
        self.record_number   = kwargs.get('record_number', 0x00)
        self.record_data     = kwargs.get('record_data', '')
        self.record_length   = kwargs.get('record_length',   len(self.record_data) // 2)
        self.response_length = kwargs.get('response_length', len(self.record_data) + 1)

    def __eq__(self, relf):
        ''' Compares the left object to the right
        '''
        return self.reference_type == relf.reference_type \
           and self.file_number    == relf.file_number    \
           and self.record_number  == relf.record_number  \
           and self.record_length  == relf.record_length  \
           and self.record_data    == relf.record_data

    def __ne__(self, relf):
        ''' Compares the left object to the right
        '''
        return not self.__eq__(relf)

    def __repr__(self):
        ''' Gives a representation of the file record
        '''
        params = (self.file_number, self.record_number, self.record_length)
        return 'FileRecord(file=%d, record=%d, length=%d)' % params


#---------------------------------------------------------------------------#
# File Requests/Responses
#---------------------------------------------------------------------------#
class ReadFileRecordRequest():
    '''
    This function code is used to perform a file record read. All request
    data lengths are provided in terms of number of bytes and all record
    lengths are provided in terms of registers.

    A file is an organization of records. Each file contains 10000 records,
    addressed 0000 to 9999 decimal or 0x0000 to 0x270f. For example, record
    12 is addressed as 12. The function can read multiple groups of
    references. The groups can be separating (non-contiguous), but the
    references within each group must be sequential. Each group is defined
    in a seperate 'sub-request' field that contains seven bytes::

        The reference type: 1 byte (must be 0x06)
        The file number: 2 bytes
        The starting record number within the file: 2 bytes
        The length of the record to be read: 2 bytes

    The quantity of registers to be read, combined with all other fields
    in the expected response, must not exceed the allowable length of the
    MODBUS PDU: 235 bytes.
    '''
    function_code = 0x14
    _rtu_byte_count_pos = 2

    def __init__(self, records=None, **kwargs):
        ''' Initializes a new instance

        :param records: The file record requests to be read
        '''           
        self.records  = records or []

    def encode(self):
        ''' Encodes the request packet

        :returns: The byte encoded packet
        '''
        packet = struct.pack('B', len(self.records) * 7)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length)
        return packet

    def decode(self, data):
        ''' Decodes the incoming request

        :param data: The data to decode into the address
        '''
        self.records = []
        byte_count = struct.unpack('B', data[0:1])[0]
        
        for count in range(1, byte_count, 7):
            decoded = struct.unpack('>BHHH', data[count:count+7])
            record  = FileRecord(file_number=decoded[1],
                record_number=decoded[2], record_length=decoded[3])
            if decoded[0] == 0x06: self.records.append(record)

    def execute(self, context):
        ''' Run a read exeception status request against the store

        :param context: The datastore to request from
        :returns: The populated response
        '''
        # TODO do some new context operation here
        # if file number, record number, or address + length
        # is too big, return an error.
        files = []
        return ReadFileRecordResponse(files)


class ReadFileRecordResponse():
    '''
    The normal response is a series of 'sub-responses,' one for each
    'sub-request.' The byte count field is the total combined count of
    bytes in all 'sub-responses.' In addition, each 'sub-response'
    contains a field that shows its own byte count.
    '''
    function_code = 0x14
    _rtu_byte_count_pos = 2

    def __init__(self, records=None, **kwargs):
        ''' Initializes a new instance

        :param records: The requested file records
        '''
        #__init__(self, **kwargs)
        self.records = records or []

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        total  = sum(record.response_length + 1 for record in self.records)
        packet = struct.pack('B', total)
        for record in self.records:
            packet += struct.pack('>BB', 0x06, record.record_length)
            packet += record.record_data
        return packet

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        count, self.records = 1, []
        byte_count = struct.unpack('B', data[0:1])[0]
        while count < byte_count:
            response_length, reference_type = struct.unpack('>BB', data[count:count+2])
            count += response_length + 1 # the count is not included
            record = FileRecord(response_length=response_length,
                record_data=data[count - response_length + 1:count])
            if reference_type != 0x06 or reference_type == 0x06 : self.records.append(record)  #fix for fuzzer
        return  self.records                                       
                

class WriteFileRecordRequest():
    '''
    This function code is used to perform a file record write. All
    request data lengths are provided in terms of number of bytes
    and all record lengths are provided in terms of the number of 16
    bit words.
    '''
    function_code = 0x15
    _rtu_byte_count_pos = 2

    def __init__(self, records=None, **kwargs):
        ''' Initializes a new instance

        :param records: The file record requests to be read
        '''
        self.records  = records or []

    def encode(self):
        ''' Encodes the request packet

        :returns: The byte encoded packet
        '''
        total_length = sum((record.record_length * 2) + 7 for record in self.records)

        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length)
            packet += record.record_data
        return packet

    def decode(self, data):
        ''' Decodes the incoming request

        :param data: The data to decode into the address
        '''
        count, self.records = 1, []
       
        byte_count = struct.unpack('B', data[0:1])[0]
        while count < byte_count:
            decoded = struct.unpack('>BHHH', data[count:count+7])
            response_length = decoded[3] * 2
            count  += response_length + 7
            record  = FileRecord(record_length=decoded[3],
                file_number=decoded[1], record_number=decoded[2],
                record_data=data[count - response_length:count])
            if decoded[0] == 0x06: self.records.append(record)


    def execute(self, context):
        ''' Run the write file record request against the context

        :param context: The datastore to request from
        :returns: The populated response
        '''
        # TODO do some new context operation here
        # if file number, record number, or address + length
        # is too big, return an error.
        return WriteFileRecordResponse(self.records)


class WriteFileRecordResponse():
    '''
    The normal response is an echo of the request.
    '''
    function_code = 0x15
    _rtu_byte_count_pos = 2

    def __init__(self, records=None, **kwargs):
        ''' Initializes a new instance

        :param records: The file record requests to be read
        '''
        
        self.records  = records or []

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        total_length = sum((record.record_length * 2) + 7 for record in self.records)
        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length)
            packet += record.record_data
        return packet

    def decode(self, data):
        ''' Decodes the incoming request

        :param data: The data to decode into the address        '''
        count, self.records = 1, []        
        byte_count = struct.unpack('B', data[0:1])[0]        
        while count < byte_count:
            decoded = struct.unpack('>BHHH', data[count:count+7])
            response_length = decoded[3] * 2
            count  += response_length + 7
            record  = FileRecord(record_length=decoded[3],
                file_number=decoded[1], record_number=decoded[2],
                record_data=data[count - response_length:count])
            if decoded[0] == 0x06: self.records.append(record)
        return  self.records   # add for fuzzer   


class MaskWriteRegisterRequest():
    '''
    This function code is used to modify the contents of a specified holding
    register using a combination of an AND mask, an OR mask, and the
    register's current contents. The function can be used to set or clear
    individual bits in the register.
    '''
    function_code = 0x16
    _rtu_frame_size = 10

    def __init__(self, address=0x0000, and_mask=0xffff, or_mask=0x0000, **kwargs):
        ''' Initializes a new instance

        :param address: The mask pointer address (0x0000 to 0xffff)
        :param and_mask: The and bitmask to apply to the register address
        :param or_mask: The or bitmask to apply to the register address
        '''
        
        self.address  = address
        self.and_mask = and_mask
        self.or_mask  = or_mask

    def encode(self):
        ''' Encodes the request packet

        :returns: The byte encoded packet
        '''
        return struct.pack('>HHH', self.address, self.and_mask, self.or_mask)

    def decode(self, data):
        ''' Decodes the incoming request

        :param data: The data to decode into the address
        '''
        (self.address, self.and_mask, self.or_mask) = struct.unpack('>HHH', data)
        return self.address, self.and_mask, self.or_mask

        

    def execute(self, context):
        ''' Run a mask write register request against the store

        :param context: The datastore to request from
        :returns: The populated response
        '''
        if not (0x0000 <= self.and_mask <= 0xffff):
            return self.doException(merror.IllegalValue)
        if not (0x0000 <= self.or_mask <= 0xffff):
            return self.doException(merror.IllegalValue)
        if not context.validate(self.function_code, self.address, 1):
            return self.doException(merror.IllegalAddress)
        values = context.getValues(self.function_code, self.address, 1)[0]
        values = ((values & self.and_mask) | self.or_mask)
        context.setValues(self.function_code, self.address, [values])
        return MaskWriteRegisterResponse(self.address, self.and_mask, self.or_mask)


class MaskWriteRegisterResponse():
    '''
    The normal response is an echo of the request. The response is returned
    after the register has been written.
    '''
    function_code = 0x16
    _rtu_frame_size = 10

    def __init__(self, address=0x0000, and_mask=0xffff, or_mask=0x0000, **kwargs):
        ''' Initializes a new instance

        :param address: The mask pointer address (0x0000 to 0xffff)
        :param and_mask: The and bitmask applied to the register address
        :param or_mask: The or bitmask applied to the register address
        '''
        
        self.address  = address
        self.and_mask = and_mask
        self.or_mask  = or_mask

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        return struct.pack('>HHH', self.address, self.and_mask, self.or_mask)

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        self.address, self.and_mask, self.or_mask = struct.unpack('>HHH', data)
        return self.address, self.and_mask, self.or_mask


class ReadFifoQueueRequest():
    '''
    This function code allows to read the contents of a First-In-First-Out
    (FIFO) queue of register in a remote device. The function returns a
    count of the registers in the queue, followed by the queued data.
    Up to 32 registers can be read: the count, plus up to 31 queued data
    registers.

    The queue count register is returned first, followed by the queued data
    registers.  The function reads the queue contents, but does not clear
    them.
    '''
    function_code = 0x18
    _rtu_frame_size = 6

    def __init__(self, address=0x0000, **kwargs):
        ''' Initializes a new instance

        :param address: The fifo pointer address (0x0000 to 0xffff)
        '''
       # __init__(self, **kwargs)
        self.address = address
        self.values = []  # this should be added to the context

    def encode(self):
        ''' Encodes the request packet

        :returns: The byte encoded packet
        '''
        return struct.pack('>H', self.address)

    def decode(self, data):
        ''' Decodes the incoming request

        :param data: The data to decode into the address
        '''
        self.address = struct.unpack('>H', data)[0]

    def execute(self, context):
        ''' Run a read exeception status request against the store

        :param context: The datastore to request from
        :returns: The populated response
        '''
        if not (0x0000 <= self.address <= 0xffff):
            return self.doException(merror.IllegalValue)
        if len(self.values) > 31:
            return self.doException(merror.IllegalValue)
        # TODO pull the values from some context
        return ReadFifoQueueResponse(self.values)


class ReadFifoQueueResponse():
    '''
    In a normal response, the byte count shows the quantity of bytes to
    follow, including the queue count bytes and value register bytes
    (but not including the error check field).  The queue count is the
    quantity of data registers in the queue (not including the count register).

    If the queue count exceeds 31, an exception response is returned with an
    error code of 03 (Illegal Data Value).
    '''
    function_code = 0x18

    @classmethod
    def calculateRtuFrameSize(cls, buffer):
        ''' Calculates the size of the message

        :param buffer: A buffer containing the data that have been received.
        :returns: The number of bytes in the response.
        '''
        hi_byte = struct.unpack(">B", buffer[2])[0]
        lo_byte = struct.unpack(">B", buffer[3])[0]
        return (hi_byte << 16) + lo_byte + 6

    def __init__(self, values=None, **kwargs):
        ''' Initializes a new instance

        :param values: The list of values of the fifo to return
        '''
        
        self.values = values or []

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        length = len(self.values) * 2
        packet = struct.pack('>HH', 2 + length, length)
        for value in self.values:
            packet += struct.pack('>H', value)
        return packet

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode
        '''
        
        self.values = []

        _, count = struct.unpack('>HH', data[0:4])
        for index in range(0, count - 4):
            idx = 4 + index * 2
            self.values.append(struct.unpack('>H', data[idx:idx + 2])[0])
        #add return value list 
        return  self.values  

class ReadWriteMultipleRegistersRequest():
    '''
    This function code performs a combination of one read operation and one
    write operation in a single MODBUS transaction. The write
    operation is performed before the read.

    Holding registers are addressed starting at zero. Therefore holding
    registers 1-16 are addressed in the PDU as 0-15.

    The request specifies the starting address and number of holding
    registers to be read as well as the starting address, number of holding
    registers, and the data to be written. The byte count specifies the
    number of bytes to follow in the write data field."
    '''
    function_code = 23
    _rtu_byte_count_pos = 10

    def __init__(self, **kwargs):
        ''' Initializes a new request message

        :param read_address: The address to start reading from
        :param read_count: The number of registers to read from address
        :param write_address: The address to start writing to
        :param write_registers: The registers to write to the specified address
        '''
        #ModbusRequest.__init__(self, **kwargs)
        self.read_address    = kwargs.get('read_address', 0x00)
        self.read_count      = kwargs.get('read_count', 0)
        self.write_address   = kwargs.get('write_address', 0x00)
        self.write_registers = kwargs.get('write_registers', None)
        if not hasattr(self.write_registers, '__iter__'):
            self.write_registers = [self.write_registers]
        self.write_count = len(self.write_registers)
        self.write_byte_count = self.write_count * 2

    def encode(self):
        ''' Encodes the request packet

        :returns: The encoded packet
        '''
        result = struct.pack('>HHHHB',
                self.read_address,  self.read_count, \
                self.write_address, self.write_count, self.write_byte_count)
        for register in self.write_registers:
            result += struct.pack('>H', register)
        return result

    def decode(self, data):
        ''' Decode the register request packet

        :param data: The request to decode
        '''
        self.read_address,  self.read_count,  \
        self.write_address, self.write_count, \
        self.write_byte_count = struct.unpack('>HHHHB', data[:9])
        self.write_registers  = []
        for i in range(9, self.write_byte_count + 9, 2):
            register = struct.unpack('>H', data[i:i + 2])[0]
            self.write_registers.append(register)

    def execute(self, context):
        ''' Run a write single register request against a datastore

        :param context: The datastore to request from
        :returns: An initialized response, exception message otherwise
        '''
        if not (1 <= self.read_count <= 0x07d):
            return self.doException(merror.IllegalValue)
        if not (1 <= self.write_count <= 0x079):
            return self.doException(merror.IllegalValue)
        if (self.write_byte_count != self.write_count * 2):
            return self.doException(merror.IllegalValue)
        if not context.validate(self.function_code, self.write_address,
                                self.write_count):
            return self.doException(merror.IllegalAddress)
        if not context.validate(self.function_code, self.read_address,
                                self.read_count):
            return self.doException(merror.IllegalAddress)
        context.setValues(self.function_code, self.write_address,
                          self.write_registers)
        registers = context.getValues(self.function_code, self.read_address,
                                      self.read_count)
        return ReadWriteMultipleRegistersResponse(registers)

    def __str__(self):
        ''' Returns a string representation of the instance

        :returns: A string representation of the instance
        '''
        params = (self.read_address, self.read_count, self.write_address,
                  self.write_count)
        return "ReadWriteNRegisterRequest R(%d,%d) W(%d,%d)" % params


class ReadWriteMultipleRegistersResponse():
    '''
    The normal response contains the data from the group of registers that
    were read. The byte count field specifies the quantity of bytes to
    follow in the read data field.
    '''
    function_code = 23
    _rtu_byte_count_pos = 2

    def __init__(self, values=None, **kwargs):
        ''' Initializes a new instance

        :param values: The register values to write
        '''
        ModbusResponse.__init__(self, **kwargs)
        self.registers = values or []

    def encode(self):
        ''' Encodes the response packet

        :returns: The encoded packet
        '''
        result = chr(len(self.registers) * 2)
        for register in self.registers:
            result += struct.pack('>H', register)
        return result

    def decode(self, data):
        ''' Decode the register response packet

        :param data: The response to decode
        '''
        bytecount = ord(data[0])
        for i in range(1, bytecount, 2):
            self.registers.append(struct.unpack('>H', data[i:i + 2])[0])

    def __str__(self):
        ''' Returns a string representation of the instance

        :returns: A string representation of the instance
        '''
        return "ReadWriteNRegisterResponse (%d)" % len(self.registers)




#---------------------------------------------------------------------------#
# Read Device Information
#---------------------------------------------------------------------------#
class ReadDeviceInformationRequest():
    '''
    This function code allows reading the identification and additional
    information relative to the physical and functional description of a
    remote device, only.

    The Read Device Identification interface is modeled as an address space
    composed of a set of addressable data elements. The data elements are
    called objects and an object Id identifies them.  
    '''
    function_code = 0x2b
    sub_function_code = 0x0e
    _rtu_frame_size = 3

    def __init__(self, read_code=None, object_id=0x00, **kwargs):
        ''' Initializes a new instance

        :param read_code: The device information read code
        :param object_id: The object to read from
        '''
        #ModbusRequest.__init__(self, **kwargs)
        self.read_code = read_code 
        self.object_id = object_id


    def encode(self):
        ''' Encodes the request packet

        :returns: The byte encoded packet
        '''
        packet = struct.pack('>BBB', self.sub_function_code,
            self.read_code, self.object_id)
        return packet

    def decode(self, data):
        ''' Decodes data part of the message.

        :param data: The incoming data
        '''
        params = struct.unpack('>BBB', data)
        self.sub_function_code, self.read_code, self.object_id = params

    def execute(self, context):
        ''' Run a read exeception status request against the store

        :param context: The datastore to request from
        :returns: The populated response
        '''
        if not (0x00 <= self.object_id <= 0xff):
            return self.doException(merror.IllegalValue)
        if not (0x00 <= self.read_code <= 0x04):
            return self.doException(merror.IllegalValue)

        information = DeviceInformationFactory.get(_MCB,
            self.read_code, self.object_id)
        return ReadDeviceInformationResponse(self.read_code, information)

    def __str__(self):
        ''' Builds a representation of the request

        :returns: The string representation of the request
        '''
        params = (self.read_code, self.object_id)
        return "ReadDeviceInformationRequest(%d,%d)" % params


class ReadDeviceInformationResponse():
    '''
    '''
    function_code = 0x2b
    sub_function_code = 0x0e

    @classmethod
    def calculateRtuFrameSize(cls, buffer):
        ''' Calculates the size of the message

        :param buffer: A buffer containing the data that have been received.
        :returns: The number of bytes in the response.
        '''
        size  = 8 # skip the header information
        count = struct.unpack('>B', buffer[7])[0]

        while count > 0:
            _, object_length = struct.unpack('>BB', buffer[size:size+2])
            size += object_length + 2
            count -= 1
        return size + 2

    def __init__(self, read_code=None, information=None, **kwargs):
        ''' Initializes a new instance

        :param read_code: The device information read code
        :param information: The requested information request
        '''
        #ModbusResponse.__init__(self, **kwargs)
        self.read_code = read_code 
        self.information = information or {}     # dictionary
        self.number_of_objects = len(self.information)
        self.conformity = 0x83 # I support everything right now

        # TODO calculate
        self.next_object_id = 0x00 # self.information[-1](0)
        self.more_follows = MoreData().Nothing

    def encode(self):
        ''' Encodes the response

        :returns: The byte encoded message
        '''
        packet = struct.pack('>BBBBBB', self.sub_function_code,
        self.read_code, self.conformity, self.more_follows,
        self.next_object_id, self.number_of_objects)

        for (object_id, data) in list(self.information.items()):
            packet += struct.pack('>BB', object_id, len(data))
            packet += data

        return packet

    def decode(self, data):
        ''' Decodes a the response

        :param data: The packet data to decode

        '''
        
        params = struct.unpack('>BBBBBB', data[0:6])
        self.sub_function_code, self.read_code = params[0:2]
        self.conformity, self.more_follows = params[2:4]
        self.next_object_id, self.number_of_objects = params[4:6]
        self.information, count = {}, 6   # skip the header information

        while count < len(data):
            if len(data[count:count+2]) ==2:
                object_id, object_length = struct.unpack('>BB', data[count:count+2]) 
            else :print(data[count:count+2]) ;break    #add for fuzzer                              
                 #object_id, object_length = struct.unpack('>BB', data[count:count+2]) 

            count += object_length + 2
            self.information[object_id] = data[count-object_length:count]

    def __str__(self):
        ''' Builds a representation of the response

        :returns: The string representation of the response
        '''
        return "ReadDeviceInformationResponse(%d)" % self.read_code

#---------------------------------------------------------------------------#
# Exported symbols
#---------------------------------------------------------------------------#
__all__ = [
    "FileRecord",
    "ReadFileRecordRequest", "ReadFileRecordResponse",
    "WriteFileRecordRequest", "WriteFileRecordResponse",
    "MaskWriteRegisterRequest", "MaskWriteRegisterResponse",
    "ReadFifoQueueRequest", "ReadFifoQueueResponse",
    "ReadWriteMultipleRegistersRequest", "ReadWriteMultipleRegistersResponse",
    "ReadDeviceInformationRequest", "ReadDeviceInformationResponse", 
]
