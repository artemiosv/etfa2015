#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2015
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
import getopt
import traceback
import math
import sys
import operator
from time import *
import logging.handlers as handlers
from datetime import datetime
import os
import signal
from random import *
import decimal
import modbus_tk
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.hooks as hooks
from modbus_tk.utils import threadsafe_function, flush_socket, to_data
from itertools import zip_longest 
import itertools
from math import ceil
from hashlib import sha256
import csv
import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.all import *
from scapy.contrib.modbus import *                  
from struct import *
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
from utils_b import *
from defines import *
import fuzz_session
#library from pymodbus software
from message import *
#The RotatingFileHandler and the coloredlogs package enables colored terminal output for Python’s logging module. 
from logging.handlers import RotatingFileHandler
from coloredlogs import ColoredFormatter
from functools import reduce
from scapy.utils import warning,get_temp_file,PcapReader,wrpcap

#Modbus tcp /basic :
#Modbus TCP PDU includes the 
#Modbus application protocol (MBAP) in addition to the Modbus application PDU used in the serial protocol
#The MBAP header has four fields: (i) transaction identifier, (ii) protocol identifier, (iii) length, 
#and (iv) unit identifier (Fig. 2). The transaction identifier permits devices to pair matching requests
#and replies on a communication channel.
#The protocol identifier indicates the application protocol encapsulated by the MBAP header (zero for Modbus).
#Since application PDUs have a maximum size of 253 bytes and the length of the MBAP is fixed at seven bytes, 
#the maximum size of a Modbus TCP data unit is 260 bytes. 

#Modbus function codes specify :
#Valid public codes fall in the non­contiguous ranges: [1, 64], [73, 99] and [111,127].
#User-defined codes in the [65, 72] and [100, 110] ranges are not considered in the Modbus standard;
#their implementations are left to vendors. 
#Reserved function codes are public codes that may be used to ensure compatibility with legacy systems. 
#Function code values in the unused range [128, 255] indicate error conditions in response messages.
#The function code for a negative response is computed by adding 128 to the function code of the request message

#------------------------------------------------------------
# Modbus TCP Messages
# ------------------------------------------------------------
# [         MBAP Header         ] [ Function Code] [ Data ]
# [ tid ][ pid ][ length ][ uid ]
#   2b     2b     2b        1b           1b           Nb
#

# Common  Function Codes Modbus 
#   01 (0x01) Read Coils
#   02 (0x02) Read Discrete Inputs
#   03 (0x03) Read Holding Registers
#   04 (0x04) Read Input Registers
#
#   05 (0x05) Write Single Coil
#   06 (0x06) Write Single Holding Register
#
#
#   15 (0x0F) Write Multiple Coils
#   16 (0x10) Write Multiple Holding Registers
#
#   17 (0x11) Report Slave ID (Serial Line only)
#   23 (0x17) Read/Write Multiple Registers   
#   22 (0x16) Mask Write Register
#
#   File record access  
#   24 (0x18) Read FIFO queue    
#   20 (0x14) Read File record  
#   21 (0x15)  Write File record 

#      Diagnostics-(Serial Line only)
#   07 (0x07) Read Exception Status 
#   08 (0x08)  Diagnostic  
#   11 (0xOB)  Get Com event counter  
#   12 (0x0C)  Get Com Event Log  
#   17 (0x11)  Report Server  ID
#  
#   43 sub code 14  (0x2B) Read device Identification  
#   43 ( 0x2B) sub code 13/14 Encapsulated Interface Transpor   
#

#-------------Exception Responses-----------

#Function Code in Request   Function Code in Exception Response
#-----------------------------------------------------------------
#  01 (01 hex) 0000 0001       129 (81 hex) 1000 0000
#  02 (02 hex) 0000 0010       130 (82 hex) 1000 0010 
#  03 (03 hex) 0000 0011       131 (83 hex) 1000 0011
#  04 (04 hex) 0000 0100       132 (84 hex) 1000 0100
#  05 (05 hex) 0000 0101       133 (85 hex) 1000 0101
#  06 (06 hex) 0000 0110       134 (86 hex) 1000 0110
#  15 (0F hex) 0000 1111       143 (8F hex) 1000 1111
#  16 (10 hex) 0001 0000       144 (90 hex) 1001 0000

#------------MODBUS Exception Codes ---------

# (01 hex) ILLEGAL FUNCTION
# (02 hex) ILLEGAL DATA ADDRESS
# (03 hex) ILLEGAL DATA VALUE
# (04 hex) SERVER  DEVICE FAILURE
# (05 hex) ACKNOWLEDGE
# (06 hex) SERVER  DEVICE BUSY
# (08 hex) MEMORY PARITY ERROR
# (0A hex) GATEWAY PATH UNAVAILABLE
# (0B hex) GATEWAY TARGET DEVICE 
#          FAILED TO RESPOND


#** Protocol modbus specification 
#----READ_COILS/ READ_DISCRETE_INPUTS

#Function code      1 Byte    0x01/0x02
#Starting Address   2 Bytes   0x0000 to 0xFFFF
#Quantity of coils  2 Bytes   1 to 2000 (0x7D0)

#-----READ_HOLDING_REGISTERS/READ_INPUT_REGISTERS 
#Function code          1   Byte    0x03/0x04
#Starting Address       2   Bytes   0x0000 to 0xFFFF
#Quantity of Registers  2   Bytes   1 to 125 (0x7D)

#------------Write Multiple Coils
#Function code          1 Byte    0x0F
#Starting Address       2 Bytes   0x0000 to 0xFFFF
#Quantity of Outputs    2 Bytes   0x0001 to 0x07B0 (1968 dec)
#Byte Count             1 Byte    N*

#---Write Multiple registers 
#Function code          1 Byte  0x10
#Quantity of Registers  2 Bytes  0x0001 to 0x007B (123 dec)
#Byte Count             1 Byte  2 x N*
#Registers Value        N* x 2 Bytes   value
#*N  = Quantity of Registers


#---------------------------------------------------------------------------------------------------------------------------------------
#This class about  dictionary of smart value, interest value and list operation fuzz testing
#smart value, interest value
#[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8195, 8196, 8197, 16383, 16384, 16385, 10000, 20000,
# 32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
# 0xFFFF+2, 99999, 100000, 500000, 1000000]:

#list for fuzzing use  invalid output_value in PDU"""
#foo_value= [0,65535]
#list of smart address for fuzzing --add value 32768 65535 and 10000, 20000,40000, 50000
#Common_add_fuz=[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535]   
#Use to Invalid_quantity, smart value contiguous registers (1 to  123 registers) for 16 (0x10)/"""
#qua_IN_REG_HO_REG=[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]                                 #Quantity   1 to 125 (0x7D)
#qua_COILS_DIS_IN=[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]         #Registers  1 to 2000 (0x7D) 

#23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121"""
#qua_WR_MU_REG_RW_Multiple=[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]
#qua_W_MUL_COILS =[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]

#Quantity  to Write  =121 /fuzze field value
#value_w_fc23= [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65533,65534,65535] 
#value_w_byte_count=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                         
#FC 20 (0x14), FC 21, fc 23 set Configuration interest value for fuzzing field PDU"""
#value_test_refer_type=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 249, 250, 251, 252, 253, 254, 255]                                          #Reference Type                                                #Reference Type list
#value_test_Byte_count=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                                      # normal x07 to 0xF5 /7-245 /one BYTES 
#value_test_file_number=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
#value_test_record_number=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
#value_test_record_length=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]

#ranges  of PDU : packet 1453 +7 = 1460 B MAX ,max packet 260B
#foo_len= [0, 1,2,3,4,5,6,7,8,9,10,255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,1462,1459,1458,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65534,65533,65535]
#FC List for choise fuzzing field PDU for each FC
#Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.User-defined codes in the ranges {65-72, 100-110}
#foo_fct= [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))]

#list operation fuzz testing 
#fp= [ 'repeat','random_pdu','remove','message']
#f_mbap=['len' ,'clone','transId', 'protoId', 'unitId', ]
#payload_pdu=['diagnostics','randByte','randBit','zerobyte','corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception']   
#f_reg=['function_code', 'starting_address', 'quantity_of_x']
#f_wr=['function_code', 'starting_address', 'output_value']
#f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
#f_read_file_rec=['function_code','Byte_Count','Reference_Type','File_number','Record_number','Record_length']
#f_write_file_rec=['Data_length','Reference_Type','File_number','Record_number','Record_length','Record_data']
#f_mask=['function_code', 'and_mask','or_mask']
#f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']
#------------------------------------------------------------------------------------------------------------------------------------------

class dict_fuzz_object(object):
    
    def __init__(self):
               
        self.Dict_lists_of_smart_value = {
            'foo_value': [0,65535],
            'foo_fct': [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))],
            'Common_add_fuz':[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,\
            16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535],
            'qua_IN_REG_HO_REG':[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,\
            32764,32769,65333,65534,65535],
            'qua_COILS_DIS_IN':[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,\
            5000,8196,10000,32762,32763,32764,32769,65333,65534,65535] ,
            'qua_WR_MU_REG_RW_Multiple':[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,\
            10000,32762,32763,32764,32769,65333,65534,65535],
            'qua_W_MUL_COILS':[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,\
            8196,10000,32762,32763,32764,32769,65333,65534,65535],
            'value_w_fc23': [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,\
            32769,65533,65534,65535],
            'value_w_byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, \
            252, 253, 254, 255],
            'value_test_refer_type':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 249, 250, 251, \
            252, 253, 254, 255],                                                                                         #Reference Type list
            'value_test_Byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, \
            255],                                     
            'value_test_file_number':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, \
            255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767,\
            32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            'value_test_record_number':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, \
            1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            'value_test_record_length':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, \
            125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, \
            16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            'foo_len': [0, 1,2,3,4,5,6,7,8,9,10,255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,\
            1462,1459,1458,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65534,65533,65535],                     
        } 

        self.Dict_fuzz_operation = {                   
            'fp': ['repeat','random_pdu','remove','message'],
            'f_mbap':['len' ,'clone','transId', 'protoId', 'unitId' ],
            'payload_pdu':['diagnostics','randByte','randBit','zerobyte','corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception'],   
            'f_reg':['function_code', 'starting_address', 'quantity_of_x'],
            'f_wr':['function_code', 'starting_address', 'output_value'],
            'f_mul_coil_reg':['function_code', 'starting_address','quantity_of_x','byte_count','value'],
            'f_read_file_rec':['function_code','Byte_Count','Reference_Type','File_number','Record_number','Record_length'],
            'f_write_file_rec':['Data_length','Reference_Type','File_number','Record_number','Record_length','Record_data'],
            'f_mask':['function_code', 'and_mask','or_mask'],
            'f_rw_reg':['function_code', 'read_count','write_count','write_byte_count', 'value'],
        }  

    #return dictionary
    def dict_smart_value(self):        
        return self.Dict_lists_of_smart_value
    #return key value
    def dict_smart_value_key(self,key):        
        return self.Dict_lists_of_smart_value.get(key)

    #return dictionary
    def dict_operation(self):        
        return self.Dict_fuzz_operation 

    #return key value
    def dict_operation_key(self,key):        
        return self.Dict_fuzz_operation.get(key)

    #to initialize multiple lists-
    def int_smart_value(self):
            fuzz_session.fp= self.dict_smart_value_key('fp')
            fuzz_session.foo_value= self.dict_smart_value_key('foo_value')            
            fuzz_session.Common_add_fuz=self.dict_smart_value_key('Common_add_fuz')
            fuzz_session.qua_IN_REG_HO_REG= self.dict_smart_value_key('qua_IN_REG_HO_REG')                                
            fuzz_session.qua_COILS_DIS_IN=self.dict_smart_value_key('qua_COILS_DIS_IN')
            fuzz_session.qua_WR_MU_REG_RW_Multiple=self.dict_smart_value_key('qua_WR_MU_REG_RW_Multiple')
            fuzz_session.qua_W_MUL_COILS =self.dict_smart_value_key('qua_W_MUL_COILS')
            fuzz_session.value_w_fc23= self.dict_smart_value_key('value_w_fc23')
            fuzz_session.value_w_byte_count=self.dict_smart_value_key('value_w_byte_count')
            fuzz_session.value_test_refer_type=self.dict_smart_value_key('value_test_refer_type')                                                                                         #Reference Type list
            fuzz_session.value_test_Byte_count= self.dict_smart_value_key('value_test_Byte_count')                                     
            fuzz_session.value_test_file_number=self.dict_smart_value_key('value_test_file_number')
            fuzz_session.value_test_record_number=self.dict_smart_value_key('value_test_record_number')
            fuzz_session.value_test_record_length=self.dict_smart_value_key('value_test_record_length')
            fuzz_session.foo_len=self.dict_smart_value_key('foo_len') 
            fuzz_session.foo_fct=self.dict_smart_value_key('foo_fct')

    def int_fuzz_operation(self):                
            fuzz_session.fp= self.dict_operation_key('fp')
            fuzz_session.f_mbap= self.dict_operation_key('f_mbap')
            fuzz_session.payload_pdu=self.dict_operation_key('payload_pdu')   
            fuzz_session.f_reg=self.dict_operation_key('f_reg')
            fuzz_session.f_wr=self.dict_operation_key('f_wr')
            fuzz_session.f_mul_coil_reg=self.dict_operation_key('f_mul_coil_reg')
            fuzz_session.f_read_file_rec=self.dict_operation_key('f_read_file_rec')
            fuzz_session.f_write_file_rec=self.dict_operation_key('f_write_file_rec')
            fuzz_session.f_mask=self.dict_operation_key('f_mask')
            fuzz_session.f_rw_reg=self.dict_operation_key('f_rw_reg')
            

#------------------------------------------------------------
# The  fuzzer function, if Connection lost re-connecting 
# start with a socket at 5-second timeout
#------------------------------------------------------------

class reconnect() :
	
    def recon_do_work(self,ever=True) :
      global host
               
      MAXIMUM_NUMBER_OF_ATTEMPTS=3                        
      lgr.info("Creating the socket reconnect")
      master1.__init__(host=host, port=502, timeout_in_sec=5.0)

      for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
          
          try:           
              master1.open_b()
              lgr.info('')
              lgr.info('\t Socket connect worked!')
              break                             
               
          #except EnvironmentError as exc:
          except socket.error:
              lgr.error(' Socket connect failed! Loop up and try socket again')               
              time.sleep( 5.0)
              continue
      else :
          lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)            
          lgr.info("Fuzzer terminate !!.")
          master1.close()
          sys.exit(1)

#------------------------------------------------------------------------------------------ 
#phase I Search FC and address and phase II fuzz testing
#Looking for send some pdu request bad,response,and exception and diagnostics
#-------------------------------------------------------------------------------------------
        
request = (
               
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\xff\xff'),           # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' \
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x00\x01'),                           # read device identification   - crash in TMW v3.26                   
        )
response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' 
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

bad = (                                                        # ITEM 12  
        (0x80, '\x80\x00\x00\x00'),                            # Unknown Function
        (0x81, '\x81\x00\x00\x00'),                            # error message
        (0x90, '\x90\x00\x00\x00'),
        (0x91, '\x91\x00\x00\x00'),
        (0x92, '\x92\x00\x00\x00'),
        (0x93, '\x93\x00\x00\x00'),
        (0x94, '\x94\x00\x00\x00'),
        (0x95, '\x95\x00\x00\x00'),
        (0x96, '\x96\x00\x00\x00'),
        (0x97, '\x97\x00\x00\x00'),
        (0x98, '\x98\x00\x00\x00'),
        (0x99, '\x99\x00\x00\x00'),                           
      )

exception = (
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
        (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
        (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception
        (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
        (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
        (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
        (0x88, '\x88\x0a\x16\x06'),                           # gateway path unavailable exception
        (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
      )


diagnostics = (
        
        (00, '\x08\x00\x00\x00\x00'),
        (0o1, '\x08\x00\x01\x00\x00'),                               #restartCommunaications
        (0o2, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (0o3, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (0o4, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (0o5, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (0o6, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (0o7, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               #ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                     #etClearModbusPlusResponse
        (20, '\x08\x00\x01\x00\xff')                                #restartCommunaications
      )

little_endian_payload = (
                       (1, '\x01\x02\x00\x03\x00\x00\x00\x04\x00\x00\x00\x00'), 
                       (2, '\x00\x00\x00\xff\xfe\xff\xfd\xff\xff\xff\xfc\xff'),
                       (3, '\xff\xff\xff\xff\xff\xff\x00\x00\xa0\x3f\x00\x00'),
                       (4, '\x00\x00\x00\x00\x19\x40\x74\x65\x73\x74\x11'),
                       )
#------------------------------------------------------------------
# This class about global variable mode search and fuzzing NOT USE  
# Use fuzz_session.py 
#-----------------------------------------------------------------
class Fuzz_session:
  fuzz = None
 
#------------------------------------------------------------
# Global variables
#------------------------------------------------------------
# prob_listi     - assigns a probability of applying the different
#                  fuzz categories
# fuzz_session   - keeps information about the current  session  fuzzer
# ip             - the IP of the machine
# host           - the IP of the remote machine (under test)
# log_file       - stores fuzzing information
# iface          - the interface of the local machine (e.g. eth0)
# search_mode     - bool ,speci are black_box or fuzzer (modbus_b.py , line 221 ..)
# running         - is the fuzzer running?
# csvFile         - stores search information
# pcap_file       - trace pcap file 
# filtered_pcap    -trace pcap file request/response modbus
# mod_file_response -trace pcap file/response modbus
# mod_file_request  -trace pcap file request/modbus


#---------------------------------------------------------------------------------------------------------------------
prob_list = [('payload', 0.5), ('field_ADU', 0.1), ('field pdu', 0.2),('two fields in message', 0.1),('Not_fuzz',0.1)]

#---------------------------------------------------------------------------------------------------------------------
host=None            
log_dir = "./log"                             # def ./dir for save log file, or create
csvFile= "" 
log_file="" 
pcap_file="" 
filtered_pcap="filtered.pcap"
mod_file_response='filter_resp.pcap'
mod_file_request='filter_req.pcap' 


class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Handler for logging to a set of files, which switches from one file
    to the next when the current file reaches a certain size, or at certain
    timed intervals
    If rotation/rollover is wanted, it doesn't make sense to use another
    mode. If for example 'w' were specified, then if there were multiple
    runs of the calling application, the logs from previous runs would be
    lost if the 'w' is respected, because the log file would be truncated
    on each run.
    """
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        
        if maxBytes > 0:
            mode = 'a'
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.
        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        """
        if self.stream is None:                 # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:                   # are we rolling over?
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)  #due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0

#-----------------------------------------------------------------------------#
# create logger- -disable log file as >>lgr.disabled = True  
#-----------------------------------------------------------------------------# 
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('')

def log_info(lgr,logger,minLevel=logging.INFO,dir='log') :
    ''' 
    set up logging to file and console
    --------Level---------------------
    DEBUG
    INFO
    WARNING
    ERROR
    FATAL/CRITICAL/EXCEPTION
    ------------------------------------
    add a rotating handler and compression, add a file handler/two separation file, 200mb / change
    add filter exeption logging.INFO from  debug log 
    You can specify particular values of maxBytes and backupCount to allow the file to rollover at
    a predetermined size.
    If backupCount is > 0, when rollover is done, no more than backupCount files are kept - the oldest ones are deleted.
    create a directory if it does not exist log_dir=./log
    Set up logging to the console-it prints to standard output
    The coloredlogs package enables colored terminal output for Python’s logging module.
     ''' 

    global filename1,filename2,log_dir
    # Define the default logging message formats.
    file_msg_format = '%(asctime)s %(levelname)-8s: %(message)s'
    console_msg_format = '%(levelname)s: %(message)s'
    
    # Validate the given directory.--NEW
    dir = os.path.normpath(dir)
  

    # Create a folder for the logfiles.
    if not os.path.exists(dir):
        os.makedirs(dir)

    lgr.setLevel(logging.INFO)    
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename1 = os.path.join(log_dir, 'info_%s.log' % now)
    filename2 = os.path.join(log_dir, 'error_%s.log' % now)
    
    fh=SizedTimedRotatingFileHandler(
    filename1, maxBytes=200*1000000, backupCount=200,                   
        when='s',interval=1000000,
        )
    #rotating handler maxBytes=  100 mb  
    fh1=SizedTimedRotatingFileHandler(                            
    filename2, maxBytes=100*1000000, backupCount=200,                      
        when='s',interval=10000000,        
        )

    fh1 = logging.FileHandler(filename2)
    fh.setLevel(logging.INFO)
    fh1.setLevel(logging.WARN)
    
    # create a formatter and set the formatter for the handler.
    frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    fh1.setFormatter(frmt)
    
    # add the Handler to the logger
    lgr.addHandler(fh)
    logger.addHandler(fh)
    lgr.addHandler(fh1)
    logger.addHandler(fh1)

    #Set up logging to the console-it prints to standard output-coloredlogs package enables   
    console_handler = logging.StreamHandler()   
    console_handler.setLevel(minLevel)
    stream_formatter = ColoredFormatter(file_msg_format)
    console_handler.setFormatter(stream_formatter)    
    ch = logging.StreamHandler()
    lgr.addHandler(console_handler)
    
#------------------------------------------------------------
# This function print info time duration and total request
#------------------------------------------------------------
def info(start_time,num_of_request):    
    import fuzz_session
    end_time = datetime.now()
    lgr.info('Duration: {}'.format(end_time - start_time))
    lgr.info('Total request : %d',fuzz_session.num_of_request) 
   
#------------------------------------------------------------
# This function cleans temporary files and stop the fuzzer 
# upon Ctrl+c event
#------------------------------------------------------------
def signal_handler(signal, frame):
   lgr.info('Stopping  Ctrl+c ')
   info(start_time,fuzz_session.num_of_request)       # info time and request
   master1.close()
   sys.exit(0)

#------------------------------------------------------------
# This function cleans temporary log files 
#------------------------------------------------------------
def Cleaning_up():   
   
   lgr.info('Cleaning up  log files')
   os.system('sudo rm -rf ' + log_dir + '*.log.*')
   os.system('sudo rm -rf ' + log_dir + '*.log')   
   
 
"""
HexByteConversion

Convert a byte string to it's hex representation for output or visa versa.

ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
"""
#--------------------------------------------------------------------------------------

# test data - different formats but equivalent data
#__hexStr1  = "FFFFFF5F8121070C0000FFFFFFFF5F8129010B"
#__hexStr2  = "FF FF FF 5F 81 21 07 0C 00 00 FF FF FF FF 5F 81 29 01 0B"
#__byteStr = "\xFF\xFF\xFF\x5F\x81\x21\x07\x0C\x00\x00\xFF\xFF\xFF\xFF\x5F\x81\x29\x01\x0B"

#----------------------------------------------------------------------------------------

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()

    return ''.join( [ "%02X " % x for x in byteStr ] ).strip()
   

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case    
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
 
    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )


# Fibonacci numbers module, write Fibonacci series up to n
def fib(n):    
    a, b = 0, 1
    while b < n:
        print(b, end=' ')
        a, b = b, a+b

# return Fibonacci series up to n
def fib2(n): 
    result = []
    a, b = 0, 1
    while b < n:
        result.append(b)
        a, b = b, a+b
    return result


def randstring(length=7):
    valid_letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join((random.choice(valid_letters) for i in range(length)))

        
def random_id(length):
    number = '0123456789'
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    format='%d,%u,%c,%n,%x,%s,\0 '
    id = ''
    for i in range(0,length,3):
        id += random.choice(number)
        id += random.choice(alpha)
        id += random.choice(format)
    return id   

def random_bit(length):
    number = '111111111111111111'
    alpha  = '000000000000000000'
    format='1111111111111111000000000000000001111111111111111000000000'
    id = ''
    for i in range(0,length,3):
        id += random.choice(number)
        id += random.choice(alpha)
        id += random.choice(format)
    return id    

#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------
def rand_XShortField():                       # random hex 2 bytes
    return random.randint(0,65535)


def rand_XByteField():                        # random hex 1 byte

   return random.randint(0,255)

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,256))


def rand_IntEnumField():
   return random.randint(0,256)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)

"""random 0 or 1 """
def rand_binary():
    return random.randint(0,1)


#convert string to hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)

# address list append boundary value
def fuzz_ad_list (first,last) :
    li=[]
    li.append((first+1))
    li.append((first+2))
    li.append((first-1))
    li.append((first-2))
    li.append(last+1)
    li.append(last+2)
    li.append(last-1)
    li.append(last-2)
    li.append((last+first)//2)
    li = [abs(item) for item in li]
    return li


class Quo:
      '''Generate random numbers using the time difference between loop
         iterations.  Quo is 'time' in Latin.
      ''' 
      def __init__(self):
        # Start time for later comparison
        self.start = datetime.now()
     
        # Sleep for a moment to allow `start` - `end` times to not be 0
        sleep(0.01)
     
      def get_raw_bytes(self, _len):
        '''Get raw random bytes, i.e., random bytes prior to hashing.'''
     
        _bytes = []
     
        for i in range(_len):
          byte = []
     
          for i in range(8):
            end = datetime.now()
            bit = int(str((self.start - end).total_seconds())[-1]) % 2
            byte.append(str(bit))
     
          _bytes.append(chr(int(''.join(byte), 2)))
        
        return ''.join(_bytes)
     
      def get_random_bytes(self, _len):
        '''Get truly random bytes, i.e., random bytes post hashing.
         sha256 wants a minimum input length of 32 bytes.  Since users
         can request any byte length, round requests up to the nearest
         32 byte chunks.
        '''    
        random_bytes = []
        
        for i in range(int(ceil(_len // 32.0))):
          raw_bytes = self.get_raw_bytes(32)    
          random_bytes.append(sha256(raw_bytes).digest())    
        return ''.join(random_bytes)[:_len]
     
             
# some def for use ,all def for fuzzer payload adu+pdu copy from unittest.py, --not use
class custom_mbap_pdu() :
    
    def testRequestErrors(self):
        ''' Test a request factory decoder exceptions '''

        for func, msg in self.bad:
            result = self.server.decode(msg)
            self.assertEqual(result.ErrorCode, 1,
                    "Failed to decode invalid requests")
            self.assertEqual(result.execute(None).function_code, func,
                    "Failed to create correct response message")    
  
    def testPack(self):
        """Test that packing a mbap give the expected result"""
        self.assertEqual(self.mbap1.pack(), struct.pack(">HHHB", 1, 2, 3, 4))
    
    def mbap_custom(self):
        """create mbap object custom"""
        mbap = modbus_tcp_b.TcpMbap_b()                            
        mbap.protocol_id = 2
        mbap.length = 0
        mbap.unit_id = 0
       
    def testBuildRequest(self):
        """Test the mbap returned by building a request"""
        query = modbus_tcp.TcpQuery()
        request = query.build_request("", 0)
        self.assertEqual(struct.pack(">HHHB", query._request_mbap.transaction_id, 0, 1, 0), request)
#   
    def testBuildRequestWithSlave(self):
        """Test the mbap returned by building a request with a slave"""
        query = modbus_tcp.TcpQuery()
        for i in range(0, 255):
            request = query.build_request("", i)
            self.assertEqual(struct.pack(">HHHB", query._request_mbap.transaction_id, 0, 1, i), request)

    def InvalidSlave(self):
        """Test that an error is raised when invalid slave is passed"""
        query = modbus_tcp.TcpQuery()
        for i in [256, 257, 65536]:
            self.assertRaises(modbus_tk.modbus.InvalidArgumentError, query.build_request, "", i)

    def testBuildRequestWithPdu(self):
        """Test the mbap returned by building a request with a pdu"""
        query = modbus_tcp.TcpQuery()
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, 0)
            self.assertEqual(struct.pack(">HHHB"+str(len(pdu))+"s", query._request_mbap.transaction_id, 0, len(pdu)+1, 0, pdu), request)
        
    def testParseRespone(self):
        """Test that Modbus TCP part of the response is understood"""
        query = modbus_tcp.TcpQuery()
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request("a", 0)
            response = struct.pack(">HHHB"+str(len(pdu))+"s", query._request_mbap.transaction_id, query._request_mbap.protocol_id, len(pdu)+1, query._request_mbap.unit_id, pdu)
            extracted = query.parse_response(response)
            self.assertEqual(extracted, pdu)

    def testParseRequest(self):
        """Test that Modbus TCP part of the request is understood"""
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, i)
            (slave, extracted_pdu) = query.parse_request(request)
            self.assertEqual(extracted_pdu, pdu)
            self.assertEqual(slave, i)
            i += 1

    def testParseRequestInvalidLength(self):
        """Test that an error is raised if the length is not valid"""
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = struct.pack(">HHHB", 0, 0, (len(pdu)+2), 0)
            self.assertRaises(modbus_tk.modbus_tcp.ModbusInvalidMbapError, query.parse_request, request+pdu)

    def testBuildResponse(self):
        """Test that the response of a req
           mbap.length = fuzzer_ADU().Invalidlen(self)uest is build properly
        """
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, i)
            response = query.build_response(pdu)
            response_pdu = query.parse_response(response)
            self.assertEqual(pdu, response_pdu)
            i += 1  
    
    def test_Write_SingleCoilIn_Value(self):
        """Check that an error is raised when writing a coil with an invalid value"""
        bad_query = struct.pack(">BBHH", 1, modbus_tk.defines.WRITE_SINGLE_COIL, 0, 1)
                        
        self.master._send(bad_query)
        response = self.master._recv()
        self.assertEqual(response[:-2], struct.pack(">BBB", 1, modbus_tk.defines.WRITE_SINGLE_COIL+128, 3))       

#-------------------------------------------------------------------------------------------------------------
# This Class fuzzes / verify function code and mapping address
#-----------------------------------------------------------------------------------------------------------
class black_box:
    global csvHeading,list_csv,csvFile,pcap_file,filtered_pcap,csv_Heading_memory,list_of_results,rang_memory
    list_csv=[]                                                              #list of list results of search
    csvHeading= ["FC_1","FC_2","IN_REG","COILS","DIS_IN","HO_REG"]
    
    #Define for storege /memory dump attack
    csv_Heading_memory=["address_read","Value"]
    rang_memory=[]                                                           #add addres eg (0,100) as tumple/etch time
    list_of_results=[]                                                       #list of list results of search/tuples
    
    def __init__(self,csvFile='',pcap_file=""):
        self.csvFile=csvFile
        self.pcap_file=pcap_file
        self.filtered_pcap=filtered_pcap
               
    # this method write results of search black box to file csv    
    def WriteCSVFile (self,csvFile):
        global csvHeading,list_csv
       
        ofile  = open(csvFile, "w")        
        writer = csv.writer(ofile, delimiter='\t')
        writer.writerow(csvHeading)                                  
        for values in zip_longest (*list_csv):
            writer.writerow(values)      
        ofile.close()    

    # this method write results of  memory dump attack to file csv  each table memory block         
    def WriteCSVblock (self,scv_table):
        
        ofile  = open(scv_table, "w")        
        writer = csv.writer(ofile,delimiter='\t')
        #writer.writerow(csv_Heading_memory)
        for values in zip_longest (rang_memory,list_of_results):
            writer.writerow(values)                                          #making header here             
        ofile.close()  


    # This method copy for pymodbus ,test_factory.py  
    def setUp(self):
        ''' Initializes the test environment '''
        
        self.request = (
               
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\0xff\xff'),          # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' 
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x04\x00'),                           # read device identification                       
        )

        self.response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' \
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

        self.bad = (
                (0x80, '\x80\x00\x00\x00'),                           # Unknown Function
                (0x81, '\x81\x00\x00\x00'),                           # error message
                (0x90, '\x90\x00\x00\x00'),
                (0x91, '\x91\x00\x00\x00'),
                (0x92, '\x92\x00\x00\x00'),
                (0x93, '\x93\x00\x00\x00'),
                (0x94, '\x94\x00\x00\x00'),
                (0x95, '\x95\x00\x00\x00'),
                (0x96, '\x96\x00\x00\x00'),
                (0x97, '\x97\x00\x00\x00'),
                (0x98, '\x98\x00\x00\x00'),
                (0x99, '\x99\x00\x00\x00'),     
        )
        
        self.exception = (
                (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
                (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
                (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
                (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception
                (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
                (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
                (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
                (0x88, '\x88\x0a\x16\x06'),                           # gateway path unavailable exception
                (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
        )
        
        self.diagnostics = (
        
        (00, '\x08\x00\x00\x00\x00'),
        (0o1, '\x08\x00\x01\x00\x00'),
        (0o2, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (0o3, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (0o4, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (0o5, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (0o6, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (0o7, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               # ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                     #etClearModbusPlusResponse
        (20, '\x08\x00\x01\x00\xff'),                               #restartCommunaications
       )


    def remove_duplicates(self,l):
        return list(set(l))

    #scan for address coil support, return list support    
    def scan_coil(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_COILS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_coil)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_INPUT_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_INPUT_REGISTERS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_DISCRETE_INPUTS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_DISCRETE_INPUTS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_dist_input)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_HOLDING_REGISTERS(self,s_address,l_address,step,list):
        global num_of_search #demo
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave,READ_HOLDING_REGISTERS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_hold_reg)
        return  list   

    #check list of support address for number of elements min 3 elements
    def chk_list_Up(self,list):
        global step,s_address,l_address,num_of_search       
        s_address=fuzz_session.s_address
        l_address=fuzz_session.l_address
        step=fuzz_session.step
                                                     
        if list==supported_address_coil :
            while step!=1 :
                step=step//2
                if  len(list) == 0:                           #empty list                                  
                    self.scan_coil(s_address,l_address,step,list)                    
                                                                                                            
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)                  
                    if len(list) == 0 :
                        max_el=0
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535              
                    #call
                    self.scan_coil(s_address,l_address,step,list)                                                                           
                                                                   
        elif list==supported_address_input_reg :
            
            while step!=1 :
                step=step//2
                if  len(list) == 0:                           #empty list                                   
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                            
                
                else  :                                       #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)          
                    if len(list) == 0 :
                    	max_el=0#min_el=min(list)
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                                            
                       
        elif list==supported_address_dist_input :
               
            while step!=1 :
                step=step//2
                if  len(list) == 0:                           #empty list                
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                           
                
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    if len(list) == 0 :
                        max_el=0#min_el=min(list) 
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                        
                     
        elif list==supported_address_hold_reg :   
            
            while step!=1 :
                step=step//2
                if  len(list) == 0:                                                              
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)                                                                 
                else  :                                       #first address 0/not empty list                
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                                        
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)                                                                             
        else :
            pass                
        return   

    #check list of support address for number of elements min 3 elements
    def chk_list_down(self,list):
        global step,s_address,l_address
        if len(list) == 0:
            pass        
        elif min(list)!=0 :
            min_el=min(list)
            step=min_el//2
            #init value
            s_address=0
            l_address=min_el                                                           
            while step!=1 :
                step=step//2
                s_address=min(list)-(2*step)
                l_address=min(list)
                
                if list==supported_address_coil:
                    self.scan_coil(s_address,l_address,step,list)
                                                    
                elif list==supported_address_dist_input :
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                   

                elif list==supported_address_hold_reg :
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)
                    
                elif list==supported_address_input_reg : 
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                                                       
        else :
            pass        
        
        return      

    # Looking for supported function codes with wall pdu request
    def ReqsupportFunc(self):     

        supportedFunc = []        
        lgr.info('\n \t  \t Looking for supported function codes..with wall pdu request')
        
        for func, msg in self.request:
            response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))                  
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))                   
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')                    
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big') 
                if returnCode > 127 and exceptionCode == 0x01:       
                  #If return function code is > 128 --> error code
                  lgr.info("Function Code "+str(func)+" not supported." )                 
                else:
                  supportedFunc.append(func)
                  lgr.info("Function Code "+str(func)+" is supported." )
            else:
              lgr.info("Function Code "+str(func)+" probably supported." )
              supportedFunc.append(func) 

        #print function list support
        lgr.info('"\n"----------------The Function code supported / pdu search--------------') 
        self.print_results_blackbox(FC =supportedFunc)
        return supportedFunc

    # Verifies which function codes are supported by a Modbus Server-copy for modlib.py
    # Returns a list with accepted function codes
    def getSupportedFunctionCodes(self):
      
      supportedFuncCodes = []

      lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic")
      for fct in range(0,127,1):                     
            pdu=struct.pack(">B",fct) + (('\x00\x00').encode()+('\x00\x01').encode())
            response_pdu=master1.execute_master(slave,pdu)
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))        
            # We are using the raw data format, because not all function
            # codes are supported out by this library.
            if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')
                
                if returnCode > 127 and (exceptionCode == 1 or exceptionCode == 3):	
                  # If return function code is > 128 --> error code
                  lgr.info("Function Code "+str(fct)+" not supported." )                  
                else:
                  supportedFuncCodes.append(fct)
                  lgr.info("Function Code "+str(fct)+" is supported." )
            else:
              lgr.info("Function Code "+str(fct)+" probably supported." )
              #not add probably supported Function Code, add supportedFuncCodes.append(fct)    
                                                  
      #print function list supported        
      lgr.info('\n-----------    The Function code supported / search FC 1-127  --------------')              
      self.print_results_blackbox(FC =supportedFuncCodes)
      return supportedFuncCodes

    def getSupportedDiagnostics(self):                     # NOT USE IN TIME/RTU 

        supportedDiagnostics = []
        # if connection == None:
        # return "Connection needs to be established first.
        # Total of 65535, function code 8, sub-function code is 2 bytes long
        lgr.info("Looking for supported diagnostics codes..")
        for i in range(0,65535):       #
          pdu="\x08"+struct.pack(">H",i)+"\x00\x00"
          response=master1.execute_master(slave,pdu)

          # We are using the raw data format, because not all function
          # codes are supported by this library.
          if response:              
              data = str(ans)
              data2 = data.encode('hex')              
              returnCode = int(data2[14:16],16)
              exceptionCode = int(data2[17:18],16)

              if returnCode > 127 and exceptionCode == 0x01:
                # If return function code is > 128 --> error code
                lgr.info("Function Code "+str(i)+" not supported.")               
              else:
                supportedDiagnostics.append(i)
                lgr.info("Diagnostics Code "+str(i)+" is supported.")
          else:
            lgr.info("Diagnostics Code "+str(i)+" probably supported.")
            supportedDiagnostics.append(i)

        return supportedDiagnostics  
         
    # Verifies which address are supported 
    # Returns a list with accepted address
    def get_Supported(self,address_fuz,response_pdu,mylist,not_resp_list): 
        returnCode=""
        exceptionCode =""
        lgr.info('The response_pdu :%r'%ByteToHex(response_pdu))
        if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')                 
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')
                lgr.info('The function_code is: %d ' % returnCode) 
                if returnCode > 127 and (exceptionCode == 2):  
                  # If return function code is > 128 --> error code
                  lgr.info("Fuzz_address "+str(address_fuz)+" not supported." )
                  lgr.info('')
                else:
                    if address_fuz not in mylist :                                            
                        mylist.append(address_fuz)
                        lgr.info("Fuzz_address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
                    else :
                        lgr.info("Fuzz_address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
        else :
              lgr.warn("Fuzz_address  "+str(address_fuz)+" probably supported." )
              #add in list of support address
              mylist.append(address_fuz)
              #add in list for not support address list for use possible later
              not_resp_list.append(address_fuz)
              
        return  mylist.sort(),not_resp_list.sort()   

    """print supported address ..for data bank  - -NOT USE  """
    def printmap_address(self,*args):
        for arg in args :       
            print('"\n"----Check for' +'%r' %arg + 'address  supported --------------', file=sys.stderr)          
            print((" ".join(map(str, list))))
        return   
  
    """Check for supported address ..for data bank"""
      
    def getaddress(self):
      global step,value_range,l_address,s_address
      response_pdu=""
      
      lgr.info('\n \t \t Looking for READ_COILS, supported address ..')      
      #check elements of the list support address/upper 
      self.chk_list_Up(supported_address_coil)
      #if min item of list not 0
      self.chk_list_down(supported_address_coil)
      
      """Check that response for read analog inputs (READ_INPUT_REGISTERS) function is ok"""
      lgr.info('\n \t \t Looking for READ_INPUT_REGISTERS supported address ..')         
      self.chk_list_Up(supported_address_input_reg)      
      #if min item of list not 0
      
      """Check that response for read digital inputs function is ok""" 
      lgr.info('\n \t \t Looking for READ_DISCRETE_INPUTS  supported address ....')      
      self.chk_list_Up(supported_address_dist_input)     
      #if min item of list not 0
      self.chk_list_down(supported_address_dist_input)
      
      """Check that response for READ_HOLDING_REGISTERS function is ok"""  
      lgr.info('\n \t \t Looking for READ_HOLDING_REGISTERS  supported address ..')    
      self.chk_list_Up(supported_address_hold_reg)
      #if min item of list not 0
      self.chk_list_down(supported_address_hold_reg) 
     
      #print  elements of the list support address
      self.print_results_blackbox(COILS =supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
      self.print_results_blackbox(NOT_RESP_COILS =not_response_address_coil,NOT_RESP_INPUT_REGISTERS=not_response_address_input_reg,NOT_RESP_DISCRETE_INPUTS=not_response_address_dist_input,NOT_RESP_HOLDING_REGISTERS=not_response_address_hold_reg)
      
      return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg 
    
    # Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
    
    """object Id Object Name / Description   Type   M/O    category  """
     
    """   0x00  VendorName                   ASCII String  Mandatory  Basic 
          0x01  ProductCode                  ASCII String  Mandatory
          0x02  MajorMinorRevision           ASCII String  Mandatory
          -----------------------------------------------------------------
          0x03  VendorUrl                    ASCII String  Optional   Regular
          0x04  ProductName                  ASCII String  Optional 
          0x05  ModelName                    ASCII String  Optional 
          0x06  UserApplicationName          ASCII String  Optional 
          0x07  Reserved                                   Optional
          …
          0x7F 
          ---------------------------------------------------------------------                                     
          0x80  Private objects may be  optionally                     Extended  
          …
          0xFF The range [0x80–0xFF]                        Optional  
          is Product device dependant                                         
          ----------------------------------------------------------------------- """
          
    ''' Read Device ID code /read_code
            DeviceInformation_Basic:  0x01 , 
            DeviceInformation_Regular= 0x02 ,
            DeviceInformation_Extended= 0x03 ,
            DeviceInformation_Specific= 0x04 , '''
    '''If the Object Id does not match any known object, the server responds as if object 0 were 
       pointed out (restart at the beginning)  '''      

    def Read_Device_Information(self):
        '''  basic message encoding                                        
        params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] }  
        handle  = ReadDeviceInformationRequest(**params)
        '''
        mei_object=[] 
        lgr.info('\n  \t \t  Looking for FC 43 : READ Device Information (Error) SubFC :14    ')
        # Read Device ID code
        for read_code in range(1,5,1) :                                    
            for object_id in range(0,127,1) :
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=master1.execute_master(slave,result)                
                if response:                
                    returnCode=int.from_bytes(response[0:1], byteorder='big')                                      
                    exceptionCode=int.from_bytes(response[1:2], byteorder='big')                      
                    if returnCode > 127 and (exceptionCode == 2 or exceptionCode == 1 or exceptionCode == 3):
                        # If return function code is > 128 --> error code
                        lgr.info('response :   ---> %r exceptionCode : %r  ' % (ByteToHex(response),exceptionCode))
                        continue
                         
                    else :                
                        message = response[1:len(response)]          #parse_response FC=43
                        if len(message)<6 :
                            lgr.info('response message ---> : %r' % ByteToHex(message))
                            continue
                         
                        '''read device information MESSAGE response  decode '''       
                        handle  = ReadDeviceInformationResponse()    # send to decode
                        handle.decode(message)   
                        lgr.info('Read Device ID code,read_code : %d '% handle.read_code )
                        lgr.info('Read Device ID code,object_id : %d '% object_id)             
                        lgr.info('Read Device ID code,conformity : %d' % handle.conformity )
                    
                        #if  Object is in list ...
                        if handle.information not in  mei_object :                
                              mei_object.append(dict(handle.information))
                else :
                    lgr.info('response :   ---> %r ' % ByteToHex(response))
                                                  
        lgr.info('\n  \t \t Test device identification summary creation .....' )        
        lgr.info("\n".join(map(str, mei_object)))


    """print supported address ..for data bank"""
    def print_results_blackbox(self,**kwargs): 
        lgr.info('')
        for name, value in kwargs.items():
            lgr.info( '{0} = {1}'.format(name, value))
        lgr.info('')
        return                

    # Looking for send  some pdu request bad,response,and exception ,and diagnostics 
    def request_check(self):     

        check_response1 = []
        check_response2 = []
        check_response3 = []
        check_response4 = []
        
        lgr.info('\n \t \t \t .........send  wall  response..'  )
        for func, msg in self.response:
            response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))                   
            check_response1.append(ByteToHex(response_pdu))
            lgr.info('response pdu ----->:%r ' % ByteToHex(response_pdu))                  
        
        lgr.info('\n \t \t \t ------ send  request bad..'  )
        for func, msg in self.bad:
            response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            check_response2.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))   
        
        lgr.info('\n  \t \t \t ..........send  exception....')
        for func, msg in self.exception:
            response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            check_response3.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))
        
        lgr.info('\n \t \t \t ........send  diagnostics..')    
        for func, msg in self.diagnostics:
            response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            check_response4.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        
        lgr.info ('\n----------------Response of request --------------')
        self.print_results_blackbox(response =check_response1,bad=check_response2,exception=check_response3,diagnostics=check_response4)
        return check_response1,check_response2,check_response3,check_response4

    """Check black_box and save csv file """
    """search.csv /file format/
        FC_1    --> Verifies which function codes are (1-127) with ModbusPDU_Generic ....
        FC_2    --> create Supported Function Codes for send request wall pdu 
        IN_REG  --> Looking for INPUT_REGISTERS  supported address
        COILS   --> Looking for READ_coil  supported address
        DIS_IN  --> Looking for DISCRETE_INPUTS  supported address
        HO_REG  --> Looking for READ_HOLDING_REGISTERS  supported address
    
    
        FC_1  FC_2    IN_REG  COILS   DIS_IN  HO_REG
           1    20       0      0        0       0
           2    43    1024    1024    1024    1024
           3          2048            2048
           4          3072            3072      ...
       ..         ....
    
    """    

    def con_SUT (self):
            global forever,search_mode,csvFile
            
            try:
                                                      
                """ Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False """
                lgr.info('\n \t Verifies which function codes are supported  .....') 
                l1=self.getSupportedFunctionCodes()   #scan  function support
                
                #Add to clobal list the return list/list of list
                list_csv.append(l1)
                             
                """Function send request wall pdu request and from response create Supported Function Codes  list""" 
                lgr.info('\n \t create Supported Function Codes for send request wall pdu  .... .....') 
                self.setUp()
                l2=self.ReqsupportFunc()
                list_csv.append(l2)
                #Add to clobal list the return lists                

                """ mapping address table      """
                l3,l4,l5,l6=self.getaddress()

                #case empty list / the PLC not response in address/return empty address list
                if len(l3) == 0:
                    l3=[0,65535]
                if len(l4)==0  : 
                    l4=[0,65535]
                if len(l5) == 0:
                    l5=[0,65535]
                if len(l6) == 0:
                    l6=[0,65535]       

                list_csv.append(l3)
                list_csv.append(l4)
                list_csv.append(l5)
                list_csv.append(l6)
               
                """ send request wall response/bad/exception """
                lgr.info('send request wall response/bad/exception ....')
                self.setUp() 
                self.request_check()
              
                """ search Device_Information """ 
                
                self.Read_Device_Information()

                """ Write to csv search results of blackbox """ 
                self.WriteCSVFile(csvFile)
                
                """ memory read dump attack"""
                self.memory_dump()           
                                                                               
            except modbus_b.ModbusError as ex:
               
               lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
               pass     
                             
          
            except socket.timeout:
                lgr.error('Socket timeout, loop and try recv() again')
                time.sleep( 5.0)
                #do_work(True)                                                  
                pass    
            
            except socket.error as socketerror:
                lgr.error("Socket Error: %s ", (socketerror))
                time.sleep( 5.0)
                do_work(True)                                                      
            
            #default
            except:                                                                             
                lgr.error('Other Socket err, exit and try creating socket again')
                traceback.print_exc()                
                time.sleep( 5.0)
                
            finally:
                    master1.close()                    
                    lgr.info("Finally! search all DONE !!.")                    
                    
    """ Read csv file and memory dump attacks

        Address 0x    --> address and offset (eg ox for COILS) ....        
        Value READ_COILS  --> Value from address    
    
       "Address 0x   Value READ_COILS"  
        (1, 100)    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1....)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ....)
        ...................
        Address 3x   Value READ_INPUT_REGISTERS "   
        (1, 100)    (3333, 1, 2, 3, 0, 5, 0, 0, 0,  0, 0, 0, 0, 0, ... 0, 0, 0, 0, ..)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0,...)

        ..
    """    
    def memory_dump(self):
        global slave,rang_memory,list_of_results, quantity, scv_table,step_mem_dump

        FCValues0 = []                                             
        FCValues1 = []
        IN_REG=[] 
        COILS=[]
        DIS_IN =[]
        HO_REG=[]

        try :
                values = csv.reader(open('search.csv', 'r'), delimiter='\t')
                #read 0 colume
                for row in values:
                      FCValues0.append(row[0])
                      FCValues1.append(row[1])
                      IN_REG.append(row[2])
                      COILS.append(row[3])
                      DIS_IN.append(row[4])
                      HO_REG.append(row[5])    
                # pop header
                FCValues0.pop(0)    
                FCValues1.pop(0)    
                IN_REG.pop(0)   
                COILS.pop(0)    
                DIS_IN.pop(0)   
                HO_REG.pop(0)
                
                IN_REG = [_f for _f in IN_REG if _f]
                COILS = [_f for _f in COILS if _f]
                DIS_IN= [_f for _f in DIS_IN if _f]
                HO_REG = [_f for _f in HO_REG if _f]
                                                           
                #convert all strings in a list to ints
                IN_REG = [int(i) for i in IN_REG]
                COILS = [int(i) for i in COILS]
                DIS_IN = [int(i) for i in DIS_IN]
                HO_REG = [int(i) for i in HO_REG]  
                
                #for all list min/max address                           
                MIN_COILS =min(COILS )
                MAX_COILS =max(COILS )
                MIN_IN_REG=min(IN_REG)
                MAX_IN_REG=max(IN_REG)
                MIN_DIS_IN=min(DIS_IN)
                MAX_DIS_IN=max(DIS_IN)
                MIN_HO_REG=min(HO_REG)
                MAX_HO_REG=max(HO_REG)
                                                                           
                lgr.info('Memory dump READ REGISTERS .... ....')                 
                lgr.info('\n')                      
                lgr.info('---------------------------- Set Configuration for memory dump attacks--------------------------------------------------------')
                lgr.info('start_address READ_COILS : %d' %MIN_COILS )
                lgr.info('last_address READ_COILS : %d' %MAX_COILS )
                lgr.info('start_address READ_DISCRETE_INPUTS: %d' %MIN_DIS_IN)
                lgr.info('last_address READ_DISCRETE_INPUTS: %d' %MAX_DIS_IN)
                lgr.info('start_address READ_HOLDING_REGISTERS: %d' %MIN_HO_REG)
                lgr.info('last_address READ_HOLDING_REGISTERS: %d' %MAX_HO_REG)
                lgr.info('start_address READ_INPUT_REGISTERS: %d' %MIN_IN_REG)
                lgr.info('last_address READ_INPUT_REGISTERS: %d' %MAX_IN_REG)
                              
                """ Test  response for read coils (READ_COILS)               
                    This function code is used to read from 1 to 2000 contiguous status of coils in a remote
                    device"""
                
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_COILS  ....(%d,%d) .offset:0X' % (MIN_COILS,MAX_COILS))               
                rang_memory.append('Address 0x \t Value READ_COILS')
                list_of_results.append('',) 
                
                for address_read in range (MIN_COILS ,MAX_COILS,step_mem_dump):                    
                        
                        if (address_read+quantity)>MAX_COILS :
                            quantity=(MAX_COILS-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        #write head for csv file
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_COILS , address_read , quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))
                        #add results for list tuples
                        list_of_results.append(result,)                       

                """ Test  response for read digital inputs function (READ_DISCRETE_INPUTS )               
                        This function code is used to read from 1 to 2000 contiguous status of discrete inputs in a
                        remote device"""
                    
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_DISCRETE_INPUTS ..(%d,%d).offset:1X'%(MIN_DIS_IN,MAX_DIS_IN))
                #offset_dis_input=10000
                rang_memory.append('Address 1x \t Value READ_DISCRETE_INPUTS ')
                list_of_results.append('',) 
                for address_read in range (MIN_DIS_IN,MAX_DIS_IN,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_DIS_IN :
                            quantity=(MAX_DIS_IN-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_DISCRETE_INPUTS, address_read , quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))                                                                  
                        list_of_results.append(result,)
                                     
                """ Test  response for read READ_INPUT_REGISTERS (READ_INPUT_REGISTERS ), offset_reg_in= 30000               
                    This function code is used to read from 1 to 125 contiguous input registers in a remote device"""                              
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_INPUT_REGISTERS ..(%d,%d)..offset: 3X' %(MIN_IN_REG,MAX_IN_REG))
                rang_memory.append('Address 3x \t Value READ_INPUT_REGISTERS ')
                list_of_results.append('',) 
                for address_read in range (MIN_IN_REG,MAX_IN_REG,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_IN_REG :
                            quantity=(MAX_IN_REG-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_INPUT_REGISTERS , address_read , quantity)    #tuple                  
                        lgr.info('Answer >> result  %s '  % (result,))
                        list_of_results.append(result,)                                          

                """ Test  response for read HOLDING_REGISTERS  (HOLDING_REGISTERS )               
                    This function code is used to read from 1 to 125 contiguous holding registers in a remote device"""
                    #Address 40001,offset_reg= 40000
                lgr.info('\n')
                lgr.info('\t \t Memory dump HOLDING_REGISTERS  ..(%d,%d)..offset:4X' % (MIN_HO_REG,MAX_HO_REG))
                rang_memory.append('Address 4x \t Value HOLDING_REGISTERS')
                list_of_results.append('',)
                
                for address_read in range (MIN_HO_REG,MAX_HO_REG ,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_HO_REG :
                            quantity=(MAX_HO_REG-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))                        
                        result=master1.execute_read_memory(slave, READ_HOLDING_REGISTERS , address_read , quantity)        #tuple                
                        lgr.info('Answer >> result  %s '  % (result,))
                        list_of_results.append(result,)     
                
                #Call function to write csv file
                self.WriteCSVblock(scv_table)                               
        except IOError:
                lgr.error('No such file or directory: search.csv')
                sys.exit(1)        
        except :
                traceback.print_exc() 
                lgr.error('error')
                pass        
                    
#-------------------------------------------------------------------------------------------------------#
# functions for read pcap file in csv file 
# Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False
# scan  function support for pcap file
#-------------------------------------------------------------------------------------------------------#
    def con_SUT_pcap (self):
            global forever,search_mode,csvFile,pcap_file,filtered_pcap,mod_file_response,mod_file_request               
            try:
                l2=[]                                      
                lgr.info('\n \t Verifies which function codes are supported  .....')                 
                l1=self.get_pkt(pcap_file)                               
                #Add to clobal list the return list/list of list
                list_csv.append(l1)
                list_csv.append(l2)                            
                # mapping address table    
                lgr.info('mapping address table ....')               
                l3,l4,l5,l6=self.getadd_pcap(filtered_pcap)
                #case empty list / the PLC not response in address/return empty address list
                if len(l3) == 0:
                    l3=[0,65535]
                if len(l4)==0  : 
                    l4=[0,65535]
                if len(l5) == 0:
                    l5=[0,65535]
                if len(l6) == 0:
                    l6=[0,65535]       

                list_csv.append(l3)
                list_csv.append(l4)
                list_csv.append(l5)
                list_csv.append(l6)
                                              
                # Write to csv search results of search  pcap file 
                self.WriteCSVFile(csvFile)                                                                                                                                 
            
            except  (KeyboardInterrupt, SystemExit):
                lgr.info("You hit control-c")
                raise           
            
            except Scapy_Exception as msg:
                lgr.error(msg, "Scapy problem ...")
                raise    
            
            except IOError as err:
                lgr.error(err.errno) 
                lgr.error(err.strerror)
            
            #default/malformed packet           
            except:                                                              
                lgr.error('Other err, continue ')
                traceback.print_exc()
                pass
                
            finally:                                        
                lgr.info("Finally! search all DONE !!.")                    
                
#--------------------------------------------------------------------
# This function reads a pcap file /filtered_pcap and returns a packet
# object /not use 
#--------------------------------------------------------------------
    def read_pcap(self,filtered_pcap):
        while not( os.path.isfile(filtered_pcap) and os.path.getsize(filtered_pcap) > 0 ):
            pass
        pkts=rdpcap(filtered_pcap)
        if len(pkts) > 0:
            return pkts[0]
        else:
            return None    

    #remove payload after TCP    /not use
    def payload_strip(pkt):
        lgr.info('payload strip')              
        cur_payload = pkt[TCP]         
        adu_pdu=cur_payload.payload     
        hexdump(adu_pdu)                
        return adu_pdu

    # read packet for pcap file  and  look for supported function codes with scapy
    # Bytes literals are always prefixed with 'b' or 'B'; they produce an instance of the bytes type instead of the str type. 
    # They may only contain ASCII characters; bytes with a numeric value of 128 or greater must be expressed with escapes.
    def get_pkt(self,pcap_file):
        supportedFuncCodes = []
        pkt_cn=0      
        lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic from pcap file")
        
        #filter by protocol, ModbusADU
        self.filter_pcap(pcap_file)                            #save in filtered.pcap/request and response
        self.filter_pcap_response(filtered_pcap)               #filtered_pcap= filtered.pcap   
        pkts=rdpcap(mod_file_response)                         #parsing/ scapy library/mod_file_response=filter_resp.pcap   
        for pkt in pkts: 
            pkt_cn +=1
            cur_payload = pkt[ModbusADUResponse]         
            pdu=cur_payload.payload                            
            response_pdu=bytes(pdu)
            
                                              
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
        
            if response_pdu:
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')                    
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')                 
                
                # If return function code is > 128 --> error code
                if returnCode > 127 and (exceptionCode == 1 or exceptionCode==3 )  :
                
                    lgr.info("Function Code "+str(returnCode )+" not supported." )                  

                elif returnCode > 127 and (exceptionCode == 1  or exceptionCode==3 or exceptionCode==2 or exceptionCode==4):
                    fcn= returnCode-128                       #exeptionCode = fc+128
                    if fcn not in supportedFuncCodes:
                        supportedFuncCodes.append(fcn)
                        lgr.info("Function Code "+str(fcn)+" is supported." )                          
                
                # If return function code is < 128 --> support                              
                elif returnCode < 127 :
                    if returnCode not in supportedFuncCodes:
                        supportedFuncCodes.append(returnCode)
                        lgr.info("Function Code "+str(returnCode)+" is supported." )                

                else :
                    lgr.warn("returnCode "+str(returnCode )+" and exceptionCode"+str(exceptionCode))                            
            
            else:
                lgr.warn("Function Code "+str(returnCode)+" probably supported.")        
        supportedFuncCodes.sort()                                                                              
        lgr.info('\n \t  \t Total packets read -----> %d '% pkt_cn)                           
        lgr.info('\n-----------    The Function code supported --------------')              
        self.print_results_blackbox(FC =supportedFuncCodes)        
        return supportedFuncCodes

   #filter by protocol, ModbusADU/capture request and response packet Modbus
   #do not care about packets, only about layers, stacked one after the other.
    def filter_pcap(self,pcap_file):   
        pkts = rdpcap(pcap_file)
        ports = [502]
        lgr.info('packets filtered ...')        
        filtered = (pkt for pkt in pkts if
            TCP in pkt and 
            ((pkt[TCP].sport in ports and pkt.getlayer(ModbusADUResponse) is not None) or (pkt[TCP].dport in ports and pkt.getlayer(ModbusADURequest))))
        wrpcap('filtered.pcap', filtered)   

    #filter by protocol,ModbusADU/capture  response packet Modbus
    #do not care about packets, only about layers, stacked one after the other.
    #filtered_pcap=filtered.pcap
    def filter_pcap_response(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].sport in ports and pkt.getlayer(ModbusADUResponse) is not None))           
        wrpcap(mod_file_response, filtered)

    #filter by protocol,ModbusADU/capture request packet Modbus
    def filter_pcap_request(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...')
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].dport in ports and pkt.getlayer(ModbusADURequest) is not None))
        wrpcap(mod_file_request, filtered)        
    

    # from request pdu in pcap file/Decode request
    # Verifies which address are supported, Returns a list with accepted address
    # list of supported address 
    def getadd_pcap(self,filtered_pcap):                                                  
        supported_address_coil = []
        supported_address_input_reg = []
        supported_address_dist_input = []
        supported_address_hold_reg = []

        #filter by protocol, ModbusADU/create filtered_request.pcap
        self.filter_pcap_request(filtered_pcap) 
        lgr.info("\n \t  \t Looking for supported address")  
        pkts=rdpcap(mod_file_request)                                                      #mod_file_request='filter_reg.pcap'
        num_packets=len(pkts)                                  
       
        # read from pkts                
        for pkt in pkts:                                                                         
        
            try:
                cur_payload = pkt[ModbusADURequest]                                        #remove payload after TCP 
                if cur_payload is None :   
                    lgr.info("Not payload ModbusADU")
                    continue
                r_pdu=cur_payload.payload 
                pdu=bytes(r_pdu)                                                               
                function_code=int.from_bytes(pdu[0:1], byteorder='big')                      
                lgr.info('Detected function_code is % s'  % function_code)                  #return tumple

      
                if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info('The read_address is %d ' % starting_address,quantity_of_x) 
                    
                    #used to read from 1 to 125 contiguous input registers/starting_address+
                    if function_code == READ_INPUT_REGISTERS:
                        #add  address in list
                        supported_address_input_reg.extend(list(range(starting_address,starting_address+quantity_of_x)))
                        lgr.info("READ_INPUT_REGISTERS address " + str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )
                    
                    #Quantity of Registers / 1 to 125 (0x7D)
                    elif function_code == READ_HOLDING_REGISTERS: 
                        #add in address in list
                        supported_address_hold_reg.extend(list(range(starting_address,starting_address+quantity_of_x))) 
                        #supported_address_hold_reg.append(starting_address)
                        lgr.info("READ_HOLDING_REGISTERS address  "+ str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )

                    # Single bit/read from 1 to 2000 contiguous status of coils /Quantity of Outputs / 8, if the remainder is different of 0 N = N+1        
                    elif function_code == READ_COILS: 
                        #add in address in list
                        #byte_count = quantity_of_x / 8  if (quantity_of_x % 8) > 0:
                        supported_address_coil.extend(list(range(starting_address,starting_address+quantity_of_x)))
                        lgr.info("READ_COILS address  "+str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )

                    elif function_code == READ_DISCRETE_INPUTS: 
                        #add in address in list
                        supported_address_dist_input.extend(list(range(starting_address,starting_address+quantity_of_x)))
                        lgr.info("READ_DISCRETE_INPUTS address  "+str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )
                    
                    else :
                        pass    

                elif function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    
                    if function_code == WRITE_SINGLE_COIL :
                        #add in address in list
                        supported_address_coil.append(starting_address)
                        lgr.info("WRITE_SINGLE_COIL address  "+str(starting_address)+" is supported." ) 

                    elif function_code == WRITE_SINGLE_REGISTER:
                        # add in address in list
                        supported_address_hold_reg.append(starting_address)
                        lgr.info("WRITE_SINGLE_REGISTER address  "+str(starting_address)+" is supported." )     
                
                elif function_code == WRITE_MULTIPLE_REGISTERS  :

                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('write_address is %d ' % starting_address)

                    if function_code == WRITE_MULTIPLE_REGISTERS :
                        #add in address in list
                        supported_address_hold_reg.extend(list(range(starting_address,starting_address+quantity_of_x)))        #calculate quantity_of_x 
                        lgr.info("WRITE_MULTIPLE_REGISTERS address  "+str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )


                    elif function_code == WRITE_MULTIPLE_COILS:
                         #add in address in list
                        supported_address_coil.extend(list(range(starting_address,starting_address+quantity_of_x)))     #calculate quantity_of_x 
                        #add    starting_address + quantity_of_x
                        lgr.info("WRITE_MULTIPLE_COILS address  "+str(list(range(starting_address,starting_address+quantity_of_x)))+" is supported." )
               
                elif function_code == Read_File_record :
                    lgr.info("Not implemented yet ..." )                    
                    pass

                # Write File Record  fc 21"""  
                elif function_code == Write_File_record : 
                    lgr.info("Not implemented yet ..." )
                    pass        

                #22 (0x16) Mask Write Register --ok"""
                elif function_code == Mask_Write_Register :
                    starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                    supported_address_hold_reg.append(starting_address)     
                    lgr.info("Mask Write Register address  "+str(starting_address)+" is supported." )

                #24 (0x18) Read FIFO Queue--ok"""
                elif function_code == Read_FIFO_queue :
                    starting_address,=struct.unpack(">H", pdu[1:3])
                    supported_address_hold_reg.append(starting_address)
                    lgr.info("Read_FIFO_queue address  "+str(starting_address)+" is supported." ) 
                    

                # 23 /( 0x17) Read_Write_Multiple_Registers -ok"""
                elif function_code == Read_Write_Multiple_Registers  :
                    #Decode request 
                    read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
                    #calculate read_count/write_count
                    supported_address_hold_reg.extend(list(range(read_address,read_address+read_count)))                                 
                    lgr.info("Read_Multiple_Registers address  "+str(list(range(read_address,read_address+read_count)))+" is supported." ) 
                    
                    supported_address_hold_reg.extend(list(range(write_address,write_address+write_count))) 
                    lgr.info("Write_Multiple_Registers address  "+str(list(range(write_address,write_address+write_count)))+" is supported.")                                

                else :
                    pass
                                
            except Scapy_Exception as msg:
                lgr.error(msg, "Scapy problem!!")
                raise
            #default
            except:                                                              
                lgr.error('err, parse packet ..')                                  
                traceback.print_exc()
                continue                
        
        #finally :
        lgr.info('\n \t \t Total packets read -----> %d' % num_packets)
                            
        #remove dumplicate item
        supported_address_coil = list(set(supported_address_coil))
        supported_address_input_reg = list(set(supported_address_input_reg))
        supported_address_dist_input = list(set(supported_address_dist_input))
        supported_address_hold_reg= list(set(supported_address_hold_reg))
        
        #Sort list 
        supported_address_coil.sort()
        supported_address_input_reg.sort()
        supported_address_dist_input.sort()
        supported_address_hold_reg.sort()

        lgr.info('\n-----------------    Check for address  supported /pcap   ----------------------')        
        self.print_results_blackbox(COILS=supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
       
        return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg     
                    
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------

#This functions fuzzes a field of pdu  (** look specif Modbus)
class fuzzer_pdu():    
    
    def __init__(self ):
        """Constructor. Set the communication settings"""        
        
        pass

    # This function  invalid record_length  fc 21
    def enc_dec_request(self, pdu):
        ''' Decodes the incoming request  +  fuzzing record_length    
        
        :params reference_type: Defaults to 0x06 (must be)
        :params file_number: Indicates which file number we are reading
        :params record_number: Indicates which record in the file
        :params record_data: The actual data of the record
        :params record_length: The length in registers of the record
        :params response_length: The length in bytes of the record
        '''
        self.reference_type  = 0x06
        self.file_number     = 0x00
        self.record_number   =  0x00
        self.record_data     =  ''

        data=pdu[1:]
        count, self.records = 1, []
        byte_count = struct.unpack('B', data[0])[0]
        
        while count < byte_count:
            decoded = struct.unpack('>BHHH', data[count:count+7])
            response_length = decoded[3] * 2
            count  += response_length + 7
            record  = FileRecord(record_length=decoded[3],
                file_number=decoded[1], record_number=decoded[2],
                record_data=data[count - response_length:count])
            if decoded[0] == 0x06: self.records.append(record)
  
        total_length = sum((record.record_length * 2) + 7 for record in self.records)
        lgr.info(total_length)
        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length+1)               #fuzz record_length +1 or ?
           
            lgr.info(' record_length : %r' % (record.record_length+1))                                           
            packet += record.record_data
            
        return packet

    # This function  invalid rec_data   fc 21    
    def enc_dec_request_rec_data(self, pdu):
        ''' Decodes the incoming request +  rec_data      
        
        :params reference_type: Defaults to 0x06 (must be)
        :params file_number: Indicates which file number we are reading
        :params record_number: Indicates which record in the file
        :params record_data: The actual data of the record
        :params record_length: The length in registers of the record
        :params response_length: The length in bytes of the record
        '''
        self.reference_type  = 0x06
        self.file_number     = 0x00
        self.record_number   =  0x00
        self.record_data     =  ''

        data=pdu[1:]
        count, self.records = 1, []
        byte_count = struct.unpack('B', data[0])[0]
        
        while count < byte_count:
            decoded = struct.unpack('>BHHH', data[count:count+7])
            response_length = decoded[3] * 2
            count  += response_length + 7
            record  = FileRecord(record_length=decoded[3],
                file_number=decoded[1], record_number=decoded[2],
                record_data=data[count - response_length:count])
            if decoded[0] == 0x06: self.records.append(record)
          
        total_length = sum((record.record_length * 2) + 7 for record in self.records)
        
        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length)                                                                     
            packet += ''.join(random_bit(record.record_length))+'\xff'+'\xff'        
            lgr.info(' record_data : %r' % ByteToHex(packet))   
                       
        return packet
    

    #----------------------------------------------------------------------------------------------------    
    # This function  invalid Reference_Type fc 20,21/normal is 6
    #---------------------------------------------------------------------------------------------------
    def Invalid_RType(self):
        #global value_test_refer_type=[0,1,2,3,4,5,7,8,9,10,11,12]
        if len(fuzz_session.value_test_refer_type) == 0:              
            Reference_Type=random.randint(12,255)
        else :    
            Reference_Type=random.choice(fuzz_session.value_test_refer_type)
            fuzz_session.value_test_refer_type.remove(Reference_Type)
        return Reference_Type
        
    #------------------------------------------------------------------------------------------------------ -------------------   
    # This function  invalid FC in pdu
    # Greate list  FC-Global foo_fct= [0,(7,8,9,11,12,17,43),range(65,73),range(100,111),range(111,128),range(73,80),range(1,65]
    # --------------------------------------------------------------------------------------------------------------------------
    def Invalidfnc(self):
        
        global flag_i       
        if flag_i==0 :
            flag_i +=1
            for i in fuzz_session.foo_fct:
                if type(i) == (tuple) or type(i) == (list) or type(i) == (range):
                    for j in i:
                        fuzz_session.fct.append(j)
                else:
                    fuzz_session.fct.append(i)                              
            random_fct =fuzz_session.fct[0] 
            return  random_fct                                                                       #Choice first elements FC                   
        else :                                                                                       
            random_fct =fuzz_session.fct[0]
            fuzz_session.fct.insert(len(fuzz_session.fct)+1,fuzz_session.fct.pop(0))                  # fist item to last 
                                                                    
            return random_fct  

    def Invalidaddress(self,function_code):
        """invalid address return out upper last_address/first address ...
            Define global, Common_add_fuz=[0,1,2,3,.32768.,65535,65534,65533] list of common fuzzing address
        """ 
        #import fuzz_session      
        if function_code == READ_COILS or function_code== WRITE_SINGLE_COIL or function_code == WRITE_MULTIPLE_COILS : 
            #select first item and rotate
            fuz_add = fuzz_session.fuzz_addre_COILS[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0            
            fuzz_session.fuzz_addre_COILS.insert(len(fuzz_session.fuzz_addre_COILS)+1,fuzz_session.fuzz_addre_COILS.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add 
        
        elif function_code == READ_DISCRETE_INPUTS :            
            fuz_add =fuzz_session.fuzz_addre_DIS_IN[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0            
            fuzz_session.fuzz_addre_DIS_IN.insert(len(fuzz_session.fuzz_addre_DIS_IN)+1,fuzz_session.fuzz_addre_DIS_IN.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add 

        elif function_code == READ_INPUT_REGISTERS :          
            fuz_add =fuzz_session.fuzz_addre_IN_REG[0]           
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0            
            fuzz_session.fuzz_addre_IN_REG.insert(len(fuzz_session.fuzz_addre_IN_REG)+1,fuzz_session.fuzz_addre_IN_REG.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add     
        
        elif function_code == READ_HOLDING_REGISTERS or function_code == WRITE_MULTIPLE_REGISTERS or function_code ==Read_Write_Multiple_Registers or function_code ==Mask_Write_Register  :           
            fuz_add =fuzz_session.fuzz_addre_HO_REG[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0           
            fuzz_session.fuzz_addre_HO_REG.insert(len(fuzz_session.fuzz_addre_HO_REG)+1,fuzz_session.fuzz_addre_HO_REG.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add 
        
        else :
            return 0
                         
        
   # FC 20,21 function  invalid quantity len data 
    def Invalid_rec_len(self):                                                  
        """invalid quantity is passed    
        global value_test_Byte_count=[0,1,2,3,4,5,6,246,247,248,249,250,251,252,253,254,255] 
        normal x07 to 0xF5 /7-245 /one BYTES, choice random if list of item fuuzing all
        """   
        if len(fuzz_session.value_test_Byte_count) == 0:                                                          
            item=random.randint(7,244)
            return item 
        else :    
            item=random.choice(fuzz_session.value_test_Byte_count)
            fuzz_session.value_test_Byte_count.remove(item)
            return item        

    #This function  invalid quantity in PDU
    def Invalid_quantity(self,function_code):
        """invalid quantity is nearest limit ,smart value.."""        
        
        # Quantity of Registers  2 Bytes   1 to 125 (0x7D)
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) :                                                              
            random_quantity=fuzz_session.qua_IN_REG_HO_REG[0]                                             
            fuzz_session.qua_IN_REG_HO_REG.insert(len(fuzz_session.qua_IN_REG_HO_REG)+1,fuzz_session.qua_IN_REG_HO_REG.pop(0))                                         
            return random_quantity
        
        elif (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
            # Quantity of Registers  2 Bytes   1 to 2000 (0x7D)                
            random_quantity= fuzz_session.qua_COILS_DIS_IN[0] 
            fuzz_session.qua_COILS_DIS_IN.insert(len(fuzz_session.qua_COILS_DIS_IN)+1,fuzz_session.qua_COILS_DIS_IN.pop(0))                  
            return random_quantity 

        #write a block of contiguous registers (1 to  123  registers) for 16 (0x10)/
        #23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121        
        elif function_code == WRITE_MULTIPLE_REGISTERS  or function_code == Read_Write_Multiple_Registers:
            random_quantity= fuzz_session.qua_WR_MU_REG_RW_Multiple[0] 
            fuzz_session.qua_WR_MU_REG_RW_Multiple.insert(len(fuzz_session.qua_WR_MU_REG_RW_Multiple)+1,fuzz_session.qua_WR_MU_REG_RW_Multiple.pop(0))                  
            return random_quantity             
           
        elif function_code == WRITE_MULTIPLE_COILS : 
            # Quantity of Registers  2 Bytes   1 to 1968
            random_quantity= fuzz_session.qua_W_MUL_COILS [0] 
            fuzz_session.qua_W_MUL_COILS.insert(len(fuzz_session.qua_W_MUL_COILS)+1,fuzz_session.qua_W_MUL_COILS.pop(0))                
            return random_quantity                  
          
        else :
            pass    
        return   1       

         
    def Invalid_output_value(self) :
        """
        global foo_value= [0,65535]
        This function  invalid output_value in PDU
        """  
        while 1 :
          n=random.randint(0,65534)        
           
          if 'n' not in fuzz_session.foo_value: 
            fuzz_session.foo_value.append(n)
            return n 
          else :                                                 
           
            random_value = random.choice(fuzz_session.foo_value)
            return random_value  

   #The functions below fuzz field PDU Modbus
    def fuzz_field_pdu(self,pdu):        
        """
        f_reg=['function_code', 'starting_address', 'quantity_of_x']
        f_wr=['function_code', 'starting_address', 'output_value']
        f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
        f_read_file_rec=['function_code', 'Byte_Count','Reference_Type','File number','Record number','Record length']
        f_write_file_rec=['Data_length','Reference_Type','File number','Record number','Record_length',Record data']
        f_mask=['function_code', 'and_mask','or_mask']
        f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']
        """
        
        global nu_reg
        if fuzz_session.fuzz_two_fields==True :                                      
        	adu=fuzzer_ADU().fuzz_field_mbap(pdu,slave)
        	fuzz_session.fuzz_two_fields==False
        else :
           adu=""
       	#extract function_code from support fc       
        (function_code,)= struct.unpack(">B", pdu[0:1])                                      
       
        lgr.info('The function_code is: %d ..0x%02X ..'  % (function_code,function_code))                       
        
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):            
              (starting_address, quantity_of_x) = struct.unpack(">HH", pdu[1:5])                            
              field = fuzz_session.f_reg[0]
              #l.insert(newindex, l.pop(oldindex))
              fuzz_session.f_reg.insert(len(fuzz_session.f_reg)+1,fuzz_session.f_reg.pop(0))                                
              lgr.info('Fuzzing field PDU: %r' % field )
              
              if field == 'function_code':
                       function_code = self.Invalidfnc()                                          
                       pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                       lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))
              elif field == 'starting_address':                     
                       starting_address=self.Invalidaddress(function_code)                       
                       pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                       lgr.info(' : %d ..0x%02X ..' % (starting_address,starting_address))                   
              elif field == 'quantity_of_x':                    
                       quantity_of_x=self.Invalid_quantity(function_code)                                                          
                       pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                       lgr.info(' : %d ..0x%02X ..' % (quantity_of_x,quantity_of_x ))                     
              else :
                       lgr.info('error')
              return adu,pdu            

        if function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
              starting_address,output_value = struct.unpack(">HH", pdu[1:5])
              field = fuzz_session.f_wr[0]
              #l.insert(newindex, l.pop(oldindex))
              fuzz_session.f_wr.insert(len(fuzz_session.f_wr)+1,fuzz_session.f_wr.pop(0))                                               
              lgr.info('Fuzzing pdu : %s '% field )

              if field == 'function_code':
                       function_code = self.Invalidfnc()      
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))                       
              elif field == 'starting_address' :              
                       starting_address=self.Invalidaddress(function_code)
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.info(' : %d ..0x%02X ..' % (starting_address,starting_address))                       
              elif field == 'output_value' :                  
                       output_value=self.Invalid_output_value()                      
                       pdu = struct.pack(">BH", function_code, starting_address)
                       pdu+= struct.pack("<H", output_value)                       
                       lgr.info(' : %d ..0x%02X ' % (output_value, output_value))
              else :
                       lgr.error('error')
                       pass
              return  adu,pdu              

        if function_code == WRITE_MULTIPLE_REGISTERS or function_code == WRITE_MULTIPLE_COILS :
              """execute modbus function 15/16"""
              # get the starting address and the number of items from the request pdu
              starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
              output_value=pdu[7:]                                                     #register value or coil value first message             
              field = fuzz_session.f_mul_coil_reg[0]
              fuzz_session.f_mul_coil_reg.insert(len(fuzz_session.f_mul_coil_reg)+1,fuzz_session.f_mul_coil_reg.pop(0))                                 
              lgr.info('Fuzzing pdu: %r' % field )                    
              list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*200, list(range(999)), (27, ), (1, 2, 3, 4), list(range(4500)),list(range(1999)),list(range(2999))]
              #output_value= random.choice(list_of_regs)                     #add more elemennts                                 
              list_of_coils = [ (1, 0, 1, 1)*2222, (0, )*3333, (1, )*2323, [0, 1]*2199, [1]*12118, [1, 1]*2256, [1, 0, 1 ,1 , 1 ,1 ,1 ]*700, (1, 0, 0, 1), [1, 0]*11110]
              #byte_value= random.choice(list_of_coils)
              #randBitList = lambda n: [randint(0,1) for b in range(1,n+1)]               
              randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List                                                               
              
              if  field== 'function_code' :
                  function_code = self.Invalidfnc()                            
                  lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                                                            
                  pdu += output_value                                   

              elif field == 'starting_address':   
                  starting_address=self.Invalidaddress(function_code)                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)
                  lgr.info(' : %d ..0x%02X ..' % (starting_address,starting_address))                 
                  pdu += output_value

              elif field == 'quantity_of_x':  
                #  quantity_of_x  - max size 123 register in one read, max allow coils 1968
                  if function_code==WRITE_MULTIPLE_REGISTERS  :             
                        quantity_of_x=self.Invalid_quantity(function_code)
                        lgr.info(' : %d ..0x%02X ..' % (quantity_of_x,quantity_of_x ))                       
                  else :                                         
                        quantity_of_x= self.Invalid_quantity(function_code)
                        lgr.info(' : %d ..0x%02X ..' % (quantity_of_x,quantity_of_x )) 
                        
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                  
                  pdu += output_value                                                 

              elif field == 'byte_count':                                                                    # number data bytes to follow len(output_value) / 8  ,2 * len(output_value)                  
                    byte_count=  rand_XByteField()                                                             
                    lgr.info(' : %d .. 0x%02X ..' % (byte_count,byte_count))
                    pdu = struct.pack(">BHHB", function_code, starting_address,  quantity_of_x, byte_count)
                    pdu += output_value                                                                                                             

              elif field == 'value':
                    pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)
         
                    if function_code==WRITE_MULTIPLE_REGISTERS : 
                      output_value= randByteList(123+len(pdu)*nu_reg)                                          #  eg (69, 68, 77, 79, 78, 83, 82, 89 ..)                     
                      nu_reg += 2
                      for j in output_value :
                        pdu += struct.pack(">H", j)                                         
                    else :                       
                      byte_value=''.join(chr(random.randint(0,255)) for _ in range(255+len(pdu)*nu_reg)) + ('\xff' + '\xff')                                                                                                   
                      nu_reg += 3
                      pdu +=  byte_value.encode()
              else :
                   lgr.error('error')
                   pass
              return  adu,pdu     

        """Read_File_record  FC 20 
           (0x14) Read File Record-test only 1 group
           test one-field + the rest valid   - 
           Each group is defined in a separate ‘sub-request’ field that contains 7 bytes:
           The reference type: 1 byte (must be specified as 6)
           The File number: 2 bytes-Indicates which file number -Extended Memory file number: 2 bytes (1 to 10, hex 0001 to 000A)
           The starting record number within the file: 2 bytes-Indicates which record in the file -(starting address)
           The length of the record to be read: 2 bytes.The length in registers of the record -(register count request)
           The available quantity of Extended Memory files depends upon the installed size
           of Extended Memory in the slave controller. Each file except the last one contains
           10,000 registers, addressed as 0000-270F hexadecimal (0000-9999 decimal). 
        """         
        if function_code == Read_File_record :
                         
            #f_read_file_rec=['function_code', 'Byte_Count','Reference_Type','File_number','Record_number','Record_length']           
            Byte_Count,Reference_Type,File_number,Record_number,Record_length=struct.unpack(">BBHHH", pdu[1:9]) 
            message = pdu[9:] 
            field = fuzz_session.f_read_file_rec[0]                                                      
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.f_read_file_rec.insert(len(fuzz_session.f_read_file_rec)+1,fuzz_session.f_read_file_rec.pop(0)) 
            lgr.info('Fuzzing PDU of Read_File_record : '+ field )
                            
            if  field== 'function_code' :
                function_code = self.Invalidfnc()                                                                                                                                                                          
                lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))                
                                                                                                                      
            elif field== 'Byte_Count' : 
                Byte_Count= self.Invalid_rec_len()                                   #normal x07 to 0xF5 /7-245 one Byte
                lgr.info(' : %d .. 0x%02X ..' % (Byte_Count,Byte_Count))
                
            elif field== 'Reference_Type' :                                          #for first group choise Reference_Type                      
                Reference_Type=self.Invalid_RType()                                  #boundary rangs 0,1,2,3,4,5,7,9,10
                lgr.info(' : %d ,,0x%02X ..' % (Reference_Type,Reference_Type))
                                
            elif field=='File_number' :
                 File_number= fuzz_session.value_test_file_number[0]                                                      
                 #l.insert(newindex, l.pop(oldindex))
                 fuzz_session.value_test_file_number.insert(len(fuzz_session.value_test_file_number)+1,fuzz_session.value_test_file_number.pop(0))                
                 lgr.info(' : %d ,,0x%02X ..' % (File_number,File_number))

            #starting address, addressed as 0000-270F hexadecimal (0000-9999 decimal).  
            elif field== 'Record_number' : 
                 Record_number=fuzz_session.value_test_record_number[0]
                 fuzz_session.value_test_record_number.insert(len(fuzz_session.value_test_record_number)+1,fuzz_session.value_test_record_number.pop(0)) 
                 lgr.info(' : %d ,,0x%02X ..' % (Record_number,Record_number))
                
            #record_length=max N=122X2 byte 244byte max, for valid len frame 
            elif field== 'Record_length' :
                 Record_length=fuzz_session.value_test_record_length[0]
                 fuzz_session.value_test_record_length.insert(len(fuzz_session.value_test_record_length)+1,fuzz_session.value_test_record_length.pop(0))  
                 lgr.info(' : %d ,,0x%02X ..' % (Record_length,Record_length))
                           
            else :
                lgr.info('not fuzzing')
            
            fuzz_session.record1='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Record_number,Record_length)      #return fuzzing record1
            pdu  = struct.pack(">BBBHHH",function_code,Byte_Count,Reference_Type,File_number,Record_number,Record_length)
            pdu += message
            return  adu,pdu
   

        """ Write File Record  FC 21
	        test one-field, the rest valid   - 
	        test_field_Write_File_record,f_write_file_rec=['Data_length','Reference_Type','File number','Record number','Record_length',Record data']
	        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
	        self.record_length = kwargs.get('record_length', len(self.record_data) / 2)
	        max value for self.record_data  is 244 Byte, self.record_length=max N=122X2 byte
         """  
        if function_code == Write_File_record :                                                                                                                                                                                          
                                                                                                                          
              Request_Data_length,Reference_Type,File_number,Record_number,Record_length= struct.unpack(">BBHHH", pdu[1:9])              
              Record_data=pdu[9:9+(Record_length*2)]
              message=pdu[9+(Record_length*2):]
              field = fuzz_session.f_write_file_rec[0]              
              #l.insert(newindex, l.pop(oldindex))
              fuzz_session.f_write_file_rec.insert(len(fuzz_session.f_write_file_rec)+1,fuzz_session.f_write_file_rec.pop(0)) 
              lgr.info('Fuzzing PDU of WRITE_File_record : '+ field )
                             
              if  field== 'function_code' :
                  function_code = self.Invalidfnc() 
                  lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))                                                                                               
                                  
              elif field== 'Data_length' : 
                  Request_Data_length= self.Invalid_rec_len()
                  lgr.info(' : %d ..0x%02X ..' % (Request_Data_length,Request_Data_length,))
                                  
              elif field== 'Reference_Type' :                                                             #for first group choise Reference_Type                      
                  Reference_Type=self.Invalid_RType()                                                     #boundary rangs 0,1,2,3,4,5,7,9,10
                  lgr.info(' : %d....0x%02X ..' % (Reference_Type,Reference_Type))

              elif field=='File_number' :
                  File_number= fuzz_session.value_test_file_number[0]                                                      
                 #l.insert(newindex, l.pop(oldindex))
                  fuzz_session.value_test_file_number.insert(len(fuzz_session.value_test_file_number)+1,fuzz_session.value_test_file_number.pop(0))                
                  lgr.info(' : %d ,,0x%02X ..' % (File_number,File_number))
              
              elif field=='Record_number' :
                  Record_number=fuzz_session.value_test_record_number[0]
                  fuzz_session.value_test_record_number.insert(len(fuzz_session.value_test_record_number)+1,fuzz_session.value_test_record_number.pop(0)) 
                  lgr.info(' : %d ,,0x%02X ..' % (Record_number,Record_number))

               #record_length=max N=122X2 byte for len 260 packet   
              elif field=='Record_length' :
                  Record_length=fuzz_session.value_test_record_length[0]
                  fuzz_session.value_test_record_length.insert(len(fuzz_session.value_test_record_length)+1,fuzz_session.value_test_record_length.pop(0))  
                  lgr.info(' : %d ,,0x%02X ..' % (Record_length,Record_length))
                   
              elif field=='Record_data' :                                                                              
                   Record_data=bytearray(random.getrandbits(8) for _ in range(self.Invalid_rec_len()))                        # smart value_test_Byte_count=[0,1,2,3,4,5,6,246,247,248,249,250,251,252,253,254,255]                   
                   lgr.info('Record_length: %d..0x%02X ,len of Record_data: %d..' % (Record_length,Record_length,len(Record_data)))                 
                   lgr.info(' : %r ' % (ByteToHex(Record_data)))
                                                 
              else :
                  lgr.info('not fuzzing')                  
              
              #return fuzzing record1
              fuzz_session.record1='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Record_number,Record_length) 
              pdu  = struct.pack(">BBBHHH",function_code,Request_Data_length,Reference_Type,File_number,Record_number,Record_length)                  
              pdu += Record_data+message              
              return  adu,pdu

        """ 22 (0x16) Mask Write Register """
        if function_code == Mask_Write_Register :

            field = fuzz_session.f_mask[0]
            fuzz_session.f_mask.insert(len(fuzz_session.f_mask)+1,fuzz_session.f_mask.pop(0)) 
            lgr.info('Mask Write Register : '+ field )
            starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
            if field == 'function_code':
                 function_code = self.Invalidfnc()                           
                 lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))
                 pdu = struct.pack(">BHHH", function_code,starting_address, and_mask, or_mask)
            
            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)
                 lgr.info(' : %d .0x%02X' % (starting_address,starting_address))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask )     

            elif field == 'or_mask' :             
                 or_mask= rand_XShortField()                                         #2 byte
                 lgr.info(' : %r .0x%02X' % (or_mask,or_mask))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask,)
            
            elif field == 'and_mask' :             
                 and_mask= rand_XShortField()                                        
                 lgr.info(' : %r .0x%02X' % (and_mask,and_mask,))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask)                    
                 
            else :                                                   
                 lgr.info('not fuzzing')                                                              
      
            return  adu,pdu 

        """24 (0x18) Read FIFO Queue--ok"""
        if function_code == Read_FIFO_queue :
             
            field = random.choice (['function_code', 'starting_address'])          
            lgr.info('Fuzzing Read_FIFO_queue pdu field :  '+ field )
            starting_address,=struct.unpack(">H", pdu[1:])                  
                      
            if field == 'function_code':
                 function_code = self.Invalidfnc()                           
                 pdu = struct.pack(">BH", function_code, starting_address)
                 lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))

            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)                 
                 pdu = struct.pack(">BH",function_code ,starting_address)
                 lgr.info(' : %d' % starting_address)
            else :                                                   
                 lgr.info('not fuzzing') 
            return  adu,pdu     

        """ 23 /( 0x17) Read_Write_Multiple_Registers """
        if function_code == Read_Write_Multiple_Registers  :
        
            field =fuzz_session.f_rw_reg[0]
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.f_rw_reg.insert(len(fuzz_session.f_rw_reg)+1,fuzz_session.f_rw_reg.pop(0))
            lgr.info('Read_Write_Multiple_Registers: ' + field )
            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List 
            list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*20, list(range(999)), (27, ), (1, 2, 3, 4), list(range(4500)),list(range(1100)),list(range(500))]           
            #Decode request for fuzz
            read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
            message=pdu[11:]
                        
            if field == 'function_code':
                 function_code = self.Invalidfnc()
                 lgr.info(' : %d ..0x%02X ..' % (function_code,function_code))                                                          
                 
            elif field == 'read_address':                     
                 read_address=self.Invalidaddress(function_code)                                        
                 lgr.info(' : %d ..0x%02X ..' % (read_address,read_address))  
            
            elif field == 'write_address':                     
                 read_address=self.Invalidaddress(function_code)                                        
                 lgr.info(' : %d ..0x%02X ..' % (write_address,write_address))  

            elif field == 'read_count' :                                                           # Quantity to Read/2 byte/ 1-125
                 read_count=self.Invalid_quantity(function_code)             
                 lgr.info(' : %d' % read_count)
                            
            elif field == 'write_count' :                                                          #Quantity to Write/2 byte /1-127       
                 write_count=self.Invalid_quantity(function_code)
                 lgr.info(' : %d' % write_count)
                                              
            elif field == 'write_byte_count' :                                                     # Write byte count/1 byte /2*N (Quantity to Write)                                                      
                 write_byte_count=fuzz_session.value_w_byte_count[0]
                 lgr.info(' : %d' % write_byte_count)
                 fuzz_session.value_w_byte_count.insert(len(fuzz_session.value_w_byte_count)+1,fuzz_session.value_w_byte_count.pop(0))
                             
            elif field == 'value':                                                                  # Quantity  to Write  1-121
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count)                          
                 output_value=bytearray(random.getrandbits(8) for _ in range(fuzz_session.value_w_fc23[0]))                                                                                                                                                              
                 lgr.info(' Register value: %d' % (len(output_value)//2))
                 lgr.info(' : %r' % (ByteToHex(output_value)))                                   
                 fuzz_session.value_w_fc23.insert(len(fuzz_session.value_w_fc23)+1,fuzz_session.value_w_fc23.pop(0))
                 return  adu,pdu+output_value
            else :                                                   
                 lgr.info('not fuzzing')                                                             
 
            pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
            pdu += message           
            return  adu,pdu                       
#----------------------------------------------------------------------------
#This class fuzzes a field of mbap (MBAP) 
#---------------------------------------------------------------------------
class fuzzer_ADU():

    def __init__(self):
        pass

    def __len__(self):
        return 0

    def TransIdIs(self):
        """the function increasing/decrasing the transaction id"""
        
        global flag_IDs       
        query = modbus_tcp_b.TcpQuery_b()
        last_transaction_id  = query.get_transaction_id_b()
        k=random.randint(2,5)

        if flag_IDs==1  :
            tr_transaction= last_transaction_id+k

            if 0<tr_transaction <65534 :
                  flag_IDs +=1                  
                  return tr_transaction
            else :                  
                  return abs(k-last_transaction_id)
        else: 
            tr_transaction= last_transaction_id-k
            if 0<tr_transaction <65534 :
                  flag_IDs -=1                  
                  return tr_transaction
            else :               
                  return abs(k-last_transaction_id)
    
    #-----------------------------------------------------------       
    # This function  invalid in the mbap len
    #------------------------------------------------------------
    def Invalidlen(self,pdu):
        """
        invalid len is passed
        fuzz_session.foo_len= [0, 1,2,3,4,5,6,7,8,9,10, ..255,256 ,257,258,259,260,261,262,263,264, ] 
        """                                                   
        random_len = fuzz_session.foo_len[0]
        fuzz_session.foo_len.insert(len(fuzz_session.foo_len)+1,fuzz_session.foo_len.pop(0))
        return random_len       

    #------------------------------------------------------------
    # This function slave invalid in the mbap 
    #------------------------------------------------------------
    def InvalidSlave(self):
        """invalid slave is passed"""        
        foo_id= []
        random_id = random.randint(0,255)
        if  'random_id'  not in foo_id:                     
                foo_id.append(random_id)
                return random_id         
        elif 'random_id' in foo_id:
                self.InvalidSlave()
        
    def mbap_custom(self):
        """create mbap custom, fuzzing all fields """
        mbap1 = modbus_tcp_b.TcpMbap_b()                              #
        mbap1.transaction_id = fuzzer_ADU().TransIdIs() 
        mbap1.protocol_id = rand_XShortField()
        mbap1.length = rand_XShortField()
        mbap1.unit_id =fuzzer_ADU().InvalidSlave()  
        return mbap1                  
    
    def fuzz_field_mbap(self,pdu,slave):
       """is define, f_mbap=['transId', 'protoId', 'unitId', 'len' ,'clone'] """      
       
       query = modbus_tcp_b.TcpQuery_b()
       mbap = modbus_tcp_b.TcpMbap_b()       
       field =fuzz_session.f_mbap[0]       
       #l.insert(newindex, l.pop(oldindex)) first element go to end
       fuzz_session.f_mbap.insert(len(fuzz_session.f_mbap)+1,fuzz_session.f_mbap.pop(0))                                                               
       lgr.info('Fuzzing field MBAP: %r' %field)
      
       if field == 'transId':   
          mbap.transaction_id= fuzzer_ADU().TransIdIs()                             
          mbap.protocol_id = 0
          mbap.length =  len(pdu)+1
          mbap.unit_id = slave                                                    
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d ..0x%02X' % (mbap.transaction_id,mbap.transaction_id))          

       elif field == 'unitId':       
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0 
          mbap.length =  len(pdu)+1
          mbap.unit_id  = fuzzer_ADU().InvalidSlave()                             
          # edit only field fuzz , struct i format (4byte)                          
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d ..0x%02X' % (mbap.unit_id,mbap.unit_id))
                      

       elif field == 'len':
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0                                                #is 0 for modbus spec
          mbap.length = fuzzer_ADU().Invalidlen(self)                         #fuzzing
          mbap.unit_id  = slave
          # edit only field fuzz , struct i format (4byte)
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d ..0x%02X' % (mbap.length,mbap.length ))
                                         
       elif field == 'protoId': 
          mbap.transaction_id=query.get_transaction_id_b()                  
          mbap.protocol_id = rand_XShortField()                               #random (0,65535)
          mbap.length = len(pdu)+1 
          mbap.unit_id  = slave 
          lgr.info(' : %d ..0x%02X' % (mbap.protocol_id,mbap.protocol_id))  
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
           
       elif field == 'clone': 
          mbap=self.mbap_custom()                                             
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )          
          lgr.info(': %d,%d,%d,%d' % (mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id))                               
          
       else:
          pass
          lgr.warn('Pass Error')
          
       lgr.info('mbap : %r ' % ByteToHex(adu))
       return adu

class fuzzer_payload :
    
    def __init__(self):
      pass        
    
    def fuzz_payload(self,pdu):
       """
       This functions fuzzes a payload
       def ne in start = [ 'repeat','remove','random_pdu','message']
       l.insert(newindex, l.pop(oldindex)) first element go to end
       """
       fuzz_type = fuzz_session.fp[0]       
       fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0)) 
       lgr.info('Fuzzing a payload : ' + fuzz_type)            
       adu,pdu=self.fuzz_payload_func[fuzz_type](pdu)   
       return adu,pdu
            
    #------------------------------------------------------------
    # This function removes a payload pdu from the packet -ok
    #------------------------------------------------------------
    def payload_remove(pdu):
       adu = ""
       lgr.info('Fuzzig a remove field pdu ')
       payloads_pdu = []  
       cur_payload = pdu    
       new_pdu=to_data('')
       pdu=new_pdu
       return adu,pdu

    #------------------------------------------------------------
    # This function inserts a random pdu payload in the packet
    #------------------------------------------------------------   
    def payload_random_pdu(pdu): 
       '''define, choice  global/payload_pdu=['diagnostics','randByte','randBit',zerobyte',corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception']      
          fuzzer_ADU().Invalidlen(pdu) , smart value for len
          l.insert(newindex, l.pop(oldindex)) first element go to end
       ''' 
       global flag_pdu 
       length=0 
       item=0           
       adu = ""                                              
       fuzz_random = fuzz_session.payload_pdu[0]       
       fuzz_session.payload_pdu.insert(len(fuzz_session.payload_pdu)+1,fuzz_session.payload_pdu.pop(0)) 
       lgr.info('Fuzzig a insert random  PDU : %r ' %fuzz_random)             
       
       if fuzz_random =='little_endian_payload' :                                   
          if flag_pdu==0 :
            i=random.randint(1,4)
            item=i                                                             # item of  pdu                                  
            for fct,msg  in little_endian_payload:
                item -= 1
                if  item == 0 :                                
                  pdu=bytearray([ ord(p) for p in msg]) 
                  flag_pdu=1
                  lgr.info('Random little_endian as PDU: %r' % ByteToHex(pdu))
                  return adu,pdu                                            
                else :
                  continue                 
          else :                                                                 #flag_pdu==1
            item=random.randrange(1,4)                                           #flag pdu=1 send pdu+++...                        
            for fct,msg  in little_endian_payload:                                                 
                pdu+=bytearray([ ord(p) for p in msg])                           #convert each char 1 byte
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random  little_endian after PDU: %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue            

       if fuzz_random =='sendbad' :                                   
          if flag_pdu==0 :
            i=random.randint(1,12)
            item=i                                                                  # item of  pdu                                  
            for fct,msg  in bad:
                item -= 1
                if  item == 0 :                                
                  pdu=bytearray([ ord(p) for p in msg]) 
                  flag_pdu=1
                  lgr.info('Random sendbad as PDU : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                                                   #flag_pdu==1
            item=random.randrange(1,12)                                            #flag pdu=1 send pdu+++...                        
            for fct,msg  in bad:                                  
                pdu+=bytearray([ ord(p) for p in msg]) 
                item -= 1
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random sendbad after PDU : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue                     

       elif fuzz_random  =='sendresponse' :                                        #flag pdu=0/send 1 response pdu
          if flag_pdu==0 :
            i=random.randint(1,20)
            item=i                                                                 # item pdu                                  
            for fct,msg  in response:
                item -= 1
                if  item == 0 :                                
                  pdu=bytearray([ ord(p) for p in msg]) 
                  flag_pdu=1
                  lgr.info('Random sendresponse as PDU : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                                                    #flag_pdu==1
            item=random.randrange(1,20)
                                                                                
            for fct,msg  in response:                                  
                pdu+=bytearray([ ord(p) for p in msg])                               #flag pdu=1 send pdu+++...
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random  sendresponse after PDU : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                          
       elif fuzz_random  =='exception' :                                             #send 1+ exception pdu
          if flag_pdu==0 : 
            i=random.randint(1,9)
            item=i                                                                   #item of  pdu                                  
            for fct,msg  in exception:
                item -= 1
                if  item == 0 :                                
                  pdu=bytearray([ ord(p) for p in msg]) 
                  flag_pdu=1
                  lgr.info('Random exception as PDU : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                                                      #flag_pdu==1
            item=random.randrange(1,9)                                                #flag pdu=1 send pdu+++...                        
            for fct,msg  in exception:                                  
                pdu+=bytearray([ ord(p) for p in msg]) 
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random exception after PDU : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                               
       elif fuzz_random  =='diagnostics' :
          if flag_pdu==0 :
            i=random.randint(1,19)
            item=i                                                                  #item in  pdu                                  
            for fct,msg  in diagnostics:
                item -= 1
                if  item == 0 :
                  fc,sub=struct.unpack(">BH", msg[0:3].encode())
                  data=rand_XShortField()                                
                  pdu=struct.pack(">BHH",fc,sub,data)                              #fc +sub +random data (0 -ffff)
                  flag_pdu=1
                  lgr.info('Random  diagnostics as PDU : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                                                   #flag_pdu==1
            item=random.randrange(1,19)                                            #flag pdu=1 send pdu+++...                        
            for fct,msg  in diagnostics:                                  
                pdu +=bytearray([ ord(p) for p in msg]) 
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random  diagnostics after PDU : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                             
       elif  fuzz_random =='randByte' :
         n_byte_len=fuzzer_ADU().Invalidlen(pdu)                                                                                 
         pdu='\x00\x00\xff\xff'+''.join(chr(random.randint(0,255)) for _ in range(n_byte_len)) + '\xff\xff'       #+2 byte +  random char +2 byte  
         lgr.info('Random  byte PDU first 20 ByteHex : %r' % ByteToHex(bytearray([ ord(p) for p in pdu[:20]])))
         return adu,bytearray([ ord(p) for p in pdu])                                      
  
       elif fuzz_random  =='randBit' : 
           n_byte_len=fuzzer_ADU().Invalidlen(pdu)                                                                                 
           pdu= '\x00\x00\xff\xff'+ ''.join(random_bit(n_byte_len))+'\xff\xff'          
           lgr.info(('Random_bit %d n_ranbit' % (n_byte_len)))           
           lgr.info('Random bit PDU first 20 ByteHex : %r' % ByteToHex(bytearray([ ord(p) for p in pdu[:20]])))       
           return adu,bytearray([ ord(p) for p in pdu]) 

       elif fuzz_random  =='zerobyte' :
           n_byte_len=fuzzer_ADU().Invalidlen(pdu)
           lgr.info(('zerobyte %d n_zero_len' % (n_byte_len)))           
           lgr.info('Zero PDU, first 20 ByteHex : %r' % ByteToHex(b"".join(struct.pack('B', random.randint(0, 0)) for _ in range(n_byte_len)[:20])))          
           return adu,b"".join(struct.pack('B', random.randint(0, 0)) for _ in range(n_byte_len))                            
       
       elif fuzz_random  =='corrupt_bytes' :
           length=len(pdu)
           n=random.randint(1,length)
           pdu=scapy.utils.corrupt_bytes(pdu, p=0.02, n=2)                                                  #corrupt_bytes random 1-len(pdu)                       
           lgr.info('Corrupt_bytes PDU : %r' % ByteToHex(pdu))                     
       
       elif fuzz_random  =='corrupt_bits' :
           length=len(pdu)
           n=random.randint(1,length)
           pdu=scapy.utils.corrupt_bits(pdu, p=0.02, n=2)                                                    #scapy library,flip a given percentage or number of bits from a string                                                                    
           lgr.info('Corrupt_bits PDU : %r' % ByteToHex(pdu))            

       else  :           
          lgr.info('None  fuzzing: %r' % pdu)
                                        
       return adu,pdu
                
    #------------------------------------------------------------
    # This function inserts a i dumple pdu payload in the packet,
    # the mbap.len invalid/not consistent
    # repait PDU isequivalent to x ^ y 
    #------------------------------------------------------------
    def payload_repeat(pdu):
        adu = ""
        global z,C
        global n_rep_pdu
        cur_payload = pdu                                               
        n_rep_pdu=int(math.pow(2, z)) + C                               
        lgr.info('Fuzzig payload_repeat PDU %r,insert %d * PDU (dumple) ' %(ByteToHex(pdu),n_rep_pdu))                                          
        pdu=n_rep_pdu*cur_payload                  
        z += 1 
        if z>16 :                                                  
            z=7
            C += 1
        
        else :
            pass               
        
        return adu,pdu 

    #  -----------------------------------------------------------------------
    # This function inserts a raw data after TCP as valid the packet Modbus/TCP
    # Generation inputs of Death 
    #-------------------------------------------------------------------------
    def payload_message(pdu):
        lgr.info('RAW data as packet Modbus/TCP')
        adu=bytearray(random.getrandbits(8) for _ in range(7))
        pdu=bytearray(random.getrandbits(8) for _ in range(len(pdu)))
        return adu,pdu      
    
    #------------------------------------------------------------
    # A map from payload fuzz type to payload fuzz function
    #------------------------------------------------------------
    fuzz_payload_func = {}
    fuzz_payload_func['repeat'] = payload_repeat           #Dumple pdu payload in the packet 
    fuzz_payload_func['remove'] = payload_remove           #Removes a payload pdu from the packet-read_packet05.py-
    fuzz_payload_func['message'] = payload_message         #Fuzzig a insert RAW data after TCP header as the packet Modbus/TCP
    fuzz_payload_func['random_pdu'] = payload_random_pdu   #insert invalid (e.g random, corrupt, exception, serial FC) PDU


class fuzzer_None:
    """ Fuzzig none, original message send"""
    def __init__(self):
      pass       
    
    def fuzz_field_None(self,pdu):
        lgr.info('None Fuzzing ')
        adu=""
        cur_payload=pdu                   
        return adu,pdu      
    

class process():
               
    #------------------------------------------------------------
    # Chooses an item from a list defined as:
    # [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
    # where prob_i is the probability of choosing item_i
    #------------------------------------------------------------
    def weighted_choice(self,items):
       weight_total = sum((item[1] for item in items))
       n = random.uniform(0, weight_total)
       for item, weight in items:
          if n < weight:
             return item
          n = n - weight
       return item


    #------------------------------------------------------------
    # When a new pdu is detected, the fuzzer also starts
    # a new session, i.e. 
    # 
    #------------------------------------------------------------
    def init_new_session(self,pdu,slave):
       global fuzz_session,num_of_request,fuzz_request
       import fuzz_session
       r=reconnect()
       lgr.info('')
       lgr.info('\t New request ------> %d',fuzz_session.num_of_request+1)      # + Num of request
       seed = time.time()                                                       #seed time  
       F_session = Fuzz_session()                                               #Class in master_fuzzer 
       fuzz_session.num_of_request += 1                                         # + Num of request all
       fuzz_session.count_num_of_fc -= 1                                        # + Num of request each FC             
       if fuzz_session.count_num_of_fc==0 :
          fuzz_session.count_num_of_fc=fuzz_session.num_of_fc
          fuzz_session.flag_reguest=False          

       F_session.fuzz = self.weighted_choice(prob_list)
       
       if fuzz_session.valid_flag==True and fuzz_session.sendvalid!=3: 
           F_session.fuzz='Not_fuzz'
           fuzz_session.sendvalid +=1
       elif fuzz_session.sendvalid==3:
           fuzz_session.valid_flag=False
           fuzz_session.sendvalid=0

       if F_session.fuzz == 'payload':
          lgr.info('Prepare to fuzz a message payload ')
          adu,pdu=fuzzer_payload().fuzz_payload(pdu)
          return adu,pdu        
       elif F_session.fuzz == 'field_ADU':
          lgr.info('Prepare to fuzz a field in MBAP')
          adu=fuzzer_ADU().fuzz_field_mbap(pdu,slave)
          return adu,pdu         
       elif F_session.fuzz == 'field pdu':
       	  fuzz_session.fuzz_two_fields=False 
          lgr.info('Prepare fuzz a field  in PDU')
          adu,pdu=fuzzer_pdu().fuzz_field_pdu(pdu)
          return adu,pdu 
       elif F_session.fuzz == 'two fields in message':
          lgr.info('Prepare fuzz two or more fields in message')
          fuzz_session.fuzz_two_fields=True                  
          adu,pdu=fuzzer_pdu().fuzz_field_pdu(pdu)                   
          return adu,pdu
       elif F_session.fuzz == 'Not_fuzz':
          lgr.info('Prepare fuzz None')
          adu,pdu=fuzzer_None().fuzz_field_None(pdu)          
          return  adu,pdu
       
class SetupAndTeardown:    
    """This is setup master object""" 

    def __init__(self,host="localhost", port=502, timeout_in_sec=1.0):

        self._timeout = timeout_in_sec
        self._host = host
        self._port = port
        self._is_opened = False
        
    def setUp(self):            
        self.master1 = modbus_tcp_b.TcpMaster_b()
        self.master1.set_timeout(5.0)
        self.master1.open()
        time.sleep(1.0)
    
    def tearDown(self):
        self.master1.close()

    
    def con (self):
                global forever,FCmergedlist, ever               
                t=TestQueries()
                r=reconnect()                 
                while True:                                                                          
                    try:
                        """fuzzer function exec """                

                        if READ_COILS in FCmergedlist:
                            
                            """Check that read coil queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 01 : READ_COILS .... ')
                            lgr.info('') 
                            t.test_readcoil()   
                            lgr.info('\t Finally!  Fuzzer READ_COILS  DONE !!.' )
                            FCmergedlist.remove(READ_COILS)                            

                        elif READ_DISCRETE_INPUTS in FCmergedlist :       

                            """Check that ReadDiscreteInputs queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 02 : READ_DISCRETE_INPUTS.... ') 
                            t.test_ReadDiscreteInputs()
                            lgr.info('\t Finally!  Fuzzer READ_DISCRETE_INPUTS!!.' )
                            FCmergedlist.remove(READ_DISCRETE_INPUTS)
                           
                        elif READ_HOLDING_REGISTERS in FCmergedlist : 
                           
                            """Check that  READ_HOLDING_REGISTERS queries are handled correctly"""
                            lgr.info('')
                            lgr.info(' \t Fuzzing  FC 03 : READ_HOLDING_REGISTERS .... ')
                            t.test_readhr()
                            lgr.info(' \t Finally!  Fuzzer READ_HOLDING_REGISTERS DONE !!.' )
                            FCmergedlist.remove(READ_HOLDING_REGISTERS)
 
                        elif READ_INPUT_REGISTERS  in FCmergedlist :
                                                   
                            """Check that  queries READ_INPUT_REGISTERS are handled correctly"""
                            lgr.info('')
                            lgr.info(' \t Fuzzing  FC 04 : READ_INPUT_REGISTERS... ') 
                            t.test_ReadAnalogInputs()
                            lgr.info('\t Finally!  Fuzzer READ_INPUT_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(READ_INPUT_REGISTERS)
                              
                        elif WRITE_SINGLE_COIL in FCmergedlist :
                           
                            """Check that write coil queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 05 : WRITE_SINGLE_COIL .... ')
                            t.test_writecoil()
                            lgr.info('\t Finally!  Fuzzer WRITE_SINGLE_COIL  DONE !!.' )
                            FCmergedlist.remove(WRITE_SINGLE_COIL)
                        
                        elif WRITE_SINGLE_REGISTER in FCmergedlist :

                            """Check that write HOLDING_REGISTERS queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 06 : WRITE_SINGLE_REGISTER.... ')
                            t.test_writesingleHr()
                            lgr.info('\t Finally!  Fuzzer WRITE_SINGLE_REGISTER  DONE !!.' )
                            FCmergedlist.remove(WRITE_SINGLE_REGISTER )

                        elif WRITE_MULTIPLE_COILS in FCmergedlist :
                     
                            """Check that write WriteMultipleCoils queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 15 : WRITE_MULTIPLE_COILS .... ')
                            t.test_WriteMultipleCoils()
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_COILS DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_COILS)                            
                        
                        elif WRITE_MULTIPLE_REGISTERS in FCmergedlist :

                            """Check that write WriteMultipleHr  queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 16 : WRITE_MULTIPLE_REGISTERS .... ')
                            t.test_WriteMultipleHr()
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_REGISTERS)
                                                  
                        #Check that an error when the request is new function from pymodbus 1.2.0                   
                        elif Read_File_record in FCmergedlist :

                            """Check that Read_File_record queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 20 : Read_File_record .... ')
                            t.test_ReadFileRecordRequestEncode()
                            lgr.info('\t Finally!  FuzzerRead_File_record  !!.' )
                            FCmergedlist.remove(Read_File_record)
                            
                        elif Write_File_record in FCmergedlist :      

                            """Check that Write_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 21 : Write_File_record .... ')
                            t.test_WriteFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzzer Write_File_record   DONE !!.' )
                            FCmergedlist.remove(Write_File_record )                            
                              
                        elif Mask_Write_Register in FCmergedlist :      

                            """Check that Mask_Write_Register queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 22 : Mask_Write_Register .... ')
                            t.test_MaskWriteRegisterRequestEncode()
                            lgr.info('\t Finally!  Mask_Write_Register DONE !!.' )
                            FCmergedlist.remove(Mask_Write_Register)                            
                              
                        elif Read_Write_Multiple_Registers in FCmergedlist :      

                            """Check that Read_Write_Multiple_Registers are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 23 : Read_Write_Multiple_Registers .... ')
                            t.test_ReadWriteMultipleRegistersRequest()
                            lgr.info('\t Finally!  Read_Write_Multiple_Registers !!.' )
                            FCmergedlist.remove(Read_Write_Multiple_Registers)
                  
                        elif Read_FIFO_queue in FCmergedlist :  

                            """Check that ReadFifoQueueRequestEncode queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 24 : Read_FIFO_queue  .... ')
                            t.test_ReadFifoQueueRequestEncode()
                            lgr.info('\t Finally!  Fuzzer Read_FIFO_queue  DONE !!.')
                            FCmergedlist.remove(Read_FIFO_queue)
                                                                    
                        else :                           
                            lgr.info('Error/Empty/not fuzzing FClist : %s' %FCmergedlist)
                            break

                    except modbus_b.ModbusError as ex:                           
                           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
                           pass                                                                                                                                                                                                     
                    #not response in defaults timeout time sec (e.g 1.0, 5.0)                                    
                    #e.g connection processing, or temporary disconnect ,
                    except socket.timeout:                                                                               
                           lgr.error('Socket disconnection, it can timeout processing/freeze/close')                                                                             
                           time.sleep(1.0)
                           
                           if fuzz_session.socket_flag==False :
                                fuzz_session.stimeout=1                                               #first time, count timeout,counter  
                                fuzz_session.socket_flag=True                                         #enable counter
                                num=fuzz_session.num_of_request
                                if fuzz_session.num_of_request-1 == num :  fuzz_session.num_recon = 0 #counter Connection lost..reconnection, after 3 valid request
                                    
                           #i already have a measurement, i look if it is continuous, socket_flag==False
                           elif (fuzz_session.num_of_request-1 == num) and (fuzz_session.stimeout!=5):                                   
                                fuzz_session.stimeout += 1
                                num=fuzz_session.num_of_request
                                if (fuzz_session.stimeout==5) :
                                        fuzz_session.socket_flag=False
                                        fuzz_session.valid_flag=True                                 #enable 3 request valid                                                                              
                                        fuzz_session.num_recon += 1                                      
                                        if fuzz_session.num_recon==2 : pass
                                        else : 
                                             lgr.info('');lgr.critical('Connection it lost after %d request..send 3 valid request..'%fuzz_session.stimeout);time.sleep(1.0)                                              
                                        if fuzz_session.num_recon==2 :
                                           fuzz_session.num_recon = 0;fuzz_session.socket_flag=False
                                           lgr.info('')
                                           lgr.critical('Connection it lost after %d request..Try reconnection !'%fuzz_session.stimeout);time.sleep(5.0)
                                           fuzz_session.stimeout=0;r.recon_do_work(ever=True) 
                                           
                           else:
                                fuzz_session.socket_flag=False
                                num=0    
                                                                
                    #e.g connection refuse,broken pipe,reset by peer -loop and try recv() again new connection ,                                   
                    except socket.error as socketerror:                                                                                                                    
                                                     
                           lgr.error("Socket Error: %s ", (socketerror))
                           time.sleep(1.0)
                           if socketerror.errno==errno.ECONNRESET or socketerror.errno==errno.EPIPE:
                               lgr.critical('Connection reset ....EPIPE..');pass            
                                
                           elif socketerror.errno==errno.ECONNREFUSED : 
                               lgr.critical('Connection refuse ......');r.recon_do_work(ever=True)
                           elif socketerror.errno == errno.ECONNABORTED: 
                               lgr.critical('ECONNABORTED ......');pass
                           elif socketerror.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                               lgr.critical('EWOULDBLOCK......');pass
                           elif (socketerror.errno  == errno.ENETRESET) or (socketerror.errno  == errno.ETIMEDOUT):
                                lgr.critical('Connection reset ....ENETRESET .. ETIMEDOUT))  ..') ;pass       
                                                                                                                                           	   
                           else:  sys.exc_clear();r.recon_do_work(ever=True)            #re-connection ,maximum number of unsuccessful attempts reached : 3                                                                     
                    
                    except:                                                             #default                         
                           lgr.error('Other  err, exit and try creating socket again')
                           traceback.print_exc()                  
                           time.sleep(5.0)
                           pass       
                                                                                                                                                                      
                lgr.info("Finally! . Fuzzer all DONE !!.")
                master1.close()                                                                                                                                                                      
   
#Read  use function of modbus_tk, script modbus.py, def execute ( ......) , execute_f is similar in modbus_b.py my script
class TestQueries(SetupAndTeardown):
    global search_mode, fuzz_mode, MIN_COILS, MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG,fuzz_request
    
    def __init__(self,address_COILS=500,COILS_quantity=1,address_DIS_IN=500,DIS_IN_quantity=1,address_HO_REG=500,HO_REG_quantity=1, address_IN_REG=500,IN_REG_quantity=1,output_value=1):

        self.address_COILS = address_COILS
        self.COILS_quantity = COILS_quantity
        self.address_DIS_IN = address_DIS_IN
        self.DIS_IN_quantity = DIS_IN_quantity
        self.address_HO_REG = address_HO_REG 
        self.HO_REG_quantity = HO_REG_quantity
        self.Write_HO_REG_quantity= HO_REG_quantity
        self.address_IN_REG=address_IN_REG
        self.IN_REG_quantity = IN_REG_quantity
        self.output_value=1 

    def test_ReadAnalogInputs(self):            
            """Test that response for read analog inputs (READ_INPUT_REGISTERS)
               quantity_of_x=value_range, value_range=1-125 
            """
            for a in range(fuzz_request):
                    if (MAX_IN_REG-MIN_IN_REG) <=5: address_fuz=MIN_IN_REG
                    else:address_fuz=random.randint(MIN_IN_REG,(MAX_IN_REG-(self.IN_REG_quantity*2)))    
                    master1.execute_f(slave,READ_INPUT_REGISTERS , address_fuz , self.IN_REG_quantity)
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
                                                   
    def test_ReadDiscreteInputs(self):
            """Test that response for read digital inputs function """                                     
            for a in range(fuzz_request):
                    if (MAX_DIS_IN-MIN_DIS_IN) <=5: address_fuz=MIN_DIS_IN
                    else:address_fuz= random.randint(MIN_DIS_IN,(MAX_DIS_IN-(self.DIS_IN_quantity*2)))
                    
                    master1.execute_f(slave,READ_DISCRETE_INPUTS , address_fuz ,self.DIS_IN_quantity )
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True          
                    
    def test_WriteMultipleHr(self):
            """Check that write WRITE_MULTIPLE_REGISTERS  queries are handled correctly/contiguous registers (1 to  123  registers                     
            values_write_hr=range(123)    1,2,3,4,...120
            (MAX_HO_REG-(self.HO_REG_quantity*2)), address_fuz+self.HO_REG_quantity*2 <MAX_HO_REG
            """
            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]                         
            for a in range(fuzz_request):
                    if (MAX_HO_REG-MIN_HO_REG) <=5: address_fuz=MIN_HO_REG
                    else:address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG-(self.HO_REG_quantity)*2)
                    master1.execute_f(slave, WRITE_MULTIPLE_REGISTERS  , address_fuz , output_value=randByteList(self.HO_REG_quantity))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True

    def test_WriteMultipleCoils(self):
            """Check that write WRITE_MULTIPLE_COILS queries are handled correctly/ max 1968 value_out
            value_out tumple
            output_value=([1]*16), [1]*16,(1, ),[0, 0, 1, 1]*8,(11,12), [0]*20,[0, 1, 0, 1]*20)
            output_value=tuple([1]*1968)
            """
            randBinList = lambda n: [randint(0,1) for b in range(1,n+1)]
                                                      
            for a in range(fuzz_request):
                    if (MAX_COILS-MIN_COILS) <=5: address_fuz=MIN_COILS 
                    else:address_fuz= random.randint(MIN_COILS,(MAX_COILS-(self.COILS_quantity*2)))   
                    master1.execute_f(slave, WRITE_MULTIPLE_COILS , address_fuz , output_value=randBinList(self.COILS_quantity))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True

    def test_writesingleHr(self):
            """Check that write HOLDING_REGISTERS queries are handled correctly"""           
            for a in range(fuzz_request): 
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)                                           
                    master1.execute_f(slave, WRITE_SINGLE_REGISTER , address_fuz , output_value=random.randint(0,65535))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True

    def test_writecoil(self):
            """Check that write one coil queries are handled correctly/Output Value  2 Bytes  0x0000 or 0xFF00"""
            for a in range(fuzz_request):                                                                       
                    address_fuz= random.randint(MIN_COILS,MAX_COILS)                                   
                    master1.execute_f(slave, WRITE_SINGLE_COIL, address_fuz , output_value=random.randint(0,1))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True                    

    def test_readcoil(self):
            """Check that read coil queries are handled correctly, read 1-2000 coil  """                                    
            for a in range(fuzz_request):
                    if (MAX_COILS-MIN_COILS) <=5: address_fuz=MIN_COILS #fix demo
                    else:address_fuz= random.randint(MIN_COILS,(MAX_COILS-(self.COILS_quantity*2)))                       
                    master1.execute_f(slave, READ_COILS, address_fuz, self.COILS_quantity)                                        
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True      

    def test_readhr(self):
            """Check that broadcast Holding register queries are handled correctly"""
            # used to read the contents of a contiguous block of holding registers 1-125 
            for a in range(fuzz_request):
                    if (MAX_HO_REG-MIN_HO_REG) <=5: address_fuz=MIN_HO_REG
                    else:address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG-(self.HO_REG_quantity)*2)
                    master1.execute_f(slave,READ_HOLDING_REGISTERS,address_fuz, self.HO_REG_quantity)
                    if fuzz_session.flag_reguest==False :
                       break
            fuzz_session.flag_reguest=True
    
    #-----------------------------------------------------------------------#
    # Read Fifo Queue FC : 24 
    #-----------------------------------------------------------------------#
    def test_ReadFifoQueueRequestEncode(self):
            """Test that response for read ReadFifoQueueRequestEncode function"""
            for a in range(fuzz_request):
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG) 
                    #Test basic bit message encoding/decoding 
                    handle  = ReadFifoQueueRequest(address_fuz)
                    result  = struct.pack(">B",Read_FIFO_queue)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    lgr.info('Answer >> Fuz_address %s response %r '  % (address_fuz,response))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True

    #---------------------------------------------------------------------------------------------------------
    # Read File Record Request FC : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
    #----------------------------------------------------------------------------------------------------------
    def test_ReadFileRecordRequestEncode(self):
            ''' 
            Test basic bit message encoding/decoding 
            The starting record number within the file: 2 bytes-Indicates which record in the file -(starting address)
            The available quantity of Extended Memory files depends upon the installed size
            of Extended Memory in the slave controller. Each file except the last one contains
            10,000 registers, addressed as 0000-270F hexadecimal (0000-9999 decimal)
            The File number: 2 bytes-Indicates which file number -Extended Memory file number: 2 bytes (1 to 10, hex 0001 to 000A)
            '''
            for a in range(fuzz_request):                
                record1  = FileRecord(file_number=0x01, record_number=0x01, record_length=0x02)
                record2  = FileRecord(file_number=0x02, record_number=0x02, record_length=0x04)
                record3  = FileRecord(file_number=0x03, record_number=0x03, record_length=0x02)
                record4  = FileRecord(file_number=0x04, record_number=0x04, record_length=0x04)                                          
                records = [record1,record2,record3,record4]
                handle  = ReadFileRecordRequest(records)
                result  = struct.pack(">B",Read_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result)
                records = [fuzz_session.record1,record2,record3,record4]                
                lgr.info('records:%r, response: %r ' % (records, response))                
                if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
   
    #------------------------------------------------------------------------------------------------------------
    # Write File Record Request FC : 21   file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
    #------------------------------------------------------------------------------------------------------------
    def test_WriteFileRecordRequestEncode(self):
            ''' Test basic bit message encoding/decoding '''
            for a in range(fuzz_request):           
                
                record1 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04')
                record2 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x0a\x0e\x04')
                record3 = FileRecord(file_number=0x02, record_number=0x03, record_data=b'\x00\x01\x02\x04')
                record4 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04')                                      
                records = [record1,record2,record3,record4]                
                handle  = WriteFileRecordRequest(records)
                result  = struct.pack(">B",Write_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result)                
                lgr.info('records:%r, response: %r ' % ([fuzz_session.record1,record2,record3,record4], response))
                if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
               
    #-----------------------------------------------------------------------------------------------------#
    # Mask Write Register Request FC:22, param :address=0x0000, and_mask=0xffff, or_mask=0x0000
    #This function code is used to modify the contents of a specified holding register 
    #The normal response is an echo of the request. The response is returned after the register 
    #has been written
    #-----------------------------------------------------------------------------------------------------#

    def test_MaskWriteRegisterRequestEncode(self):
        and_mask= 0x0000                                               # 0x0000 to 0xFFFF random ??
        or_mask= 0xFFFF                                                # 0x0000 to 0xFFFF       
        ''' Test basic bit message encoding '''
        for a in range(fuzz_request):
                address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)
                and_mask= rand_XShortField()                          # 0x0000 to 0xFFFF random ??
                or_mask = rand_XShortField()                
                handle  = MaskWriteRegisterRequest(address_fuz, and_mask, or_mask)
                result  = struct.pack(">B",Mask_Write_Register)+handle.encode()                
                response=master1.execute_fpdu(slave,result)
                lgr.info('answer >> address_fuz: %s .0x%02X   response: %r'  % (address_fuz,address_fuz,response))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
    

    #---------------------------------------------------------------------------------------------------------#
    #Read/Write Multiple registers  >FC: 23 (0x17)
    #This function code performs a combination of one read operation and one write operation in a single MODBUS transaction
    #------------------------------------------------------
    #Read Starting Address  2 Bytes  0x0000 to 0xFFFF
    #Quantity to Read  2 Bytes  0x0001 to 0x007D /1-125
    #Write Starting Address  2 Bytes  0x0000 to 0xFFFF
    #Quantity  to Write   2 Bytes  0x0001 to 0X0079  /1-121
    #Write Byte Count  1 Byte  2 x N*
    #Write Registers Value  N*x 2 Bytes  
    #*N  = Quantity to Write
    #----------------------------------------------------------------------------------------------------------#          
    
    def test_ReadWriteMultipleRegistersRequest(self):
        
        randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List               
        for a in range(fuzz_request):            
            address_write= (MIN_HO_REG+MAX_HO_REG)//3 
            address_read = (MIN_HO_REG+MAX_HO_REG)//2             
                                   
            arguments = {
                        'read_address':  address_read, 'read_count': self.HO_REG_quantity,
                        'write_address': address_write, 'write_registers':randByteList (random.randint(0,self.HO_REG_quantity)),    
                        } 
            handle  = ReadWriteMultipleRegistersRequest(**arguments)            
            result = struct.pack(">B",Read_Write_Multiple_Registers)+handle.encode()            
            response=master1.execute_fpdu(slave,result)           
            lgr.info('Answer >> address_fuz: %r write_address: %r response: %r' % (address_read,address_write,response))            
            if fuzz_session.flag_reguest==False :
                        break
        fuzz_session.flag_reguest=True    

#------------------------------------------------------------------
#Read csv file for config fuzzer/calc fuzz address list
#------------------------------------------------------------------
def Read_CSvFile():
    global start_address,last_address,mem_step,FCmergedlist,MIN_COILS,MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG 
    FCValues0 = []                                             
    FCValues1 = []
    IN_REG=[] 
    COILS=[]
    DIS_IN =[]
    HO_REG=[]
    p=dict_fuzz_object()   

    try :
            values = csv.reader(open('search.csv', 'r'), delimiter='\t')
            #read 0 colume
            for row in values:
                  FCValues0.append(row[0])
                  FCValues1.append(row[1])
                  IN_REG.append(row[2])
                  COILS.append(row[3])
                  DIS_IN.append(row[4])
                  HO_REG.append(row[5])    
            # pop header
            FCValues0.pop(0)    
            FCValues1.pop(0)    
            IN_REG.pop(0)   
            COILS.pop(0)    
            DIS_IN.pop(0)   
            HO_REG.pop(0)

            FCmergedlist = FCValues0 + FCValues1                          #Merge list of FC         
            FCmergedlist = [_f for _f in FCmergedlist if _f]              #remove all empty strings/and dumple item
            FCmergedlist=list(set(FCmergedlist))                          #fix for  version python  >2.7.15
            

            IN_REG = [_f for _f in IN_REG if _f]
            COILS = [_f for _f in COILS if _f]
            DIS_IN= [_f for _f in DIS_IN if _f]
            HO_REG = [_f for _f in HO_REG if _f]
                        
            FCmergedlist = [int(i) for i in FCmergedlist]                 #convert all strings in a list to ints
            FCmergedlist.sort(reverse=False) 
            IN_REG = [int(i) for i in IN_REG]
            COILS = [int(i) for i in COILS]
            DIS_IN = [int(i) for i in DIS_IN]
            HO_REG = [int(i) for i in HO_REG]  
            
            #for all list min/max address                       
            MIN_COILS =min(COILS )
            MAX_COILS =max(COILS )
            MIN_IN_REG=min(IN_REG)
            MAX_IN_REG=max(IN_REG)
            MIN_DIS_IN=min(DIS_IN)
            MAX_DIS_IN=max(DIS_IN)
            MIN_HO_REG=min(HO_REG)
            MAX_HO_REG=max(HO_REG)
                                   
            #calculate fuzz address for coils and register
            fuzz_session.fuzz_addre_COILS=fuzz_ad_list (MIN_COILS,MAX_COILS)+fuzz_session.Common_add_fuz
            fuzz_session.fuzz_addre_DIS_IN=fuzz_ad_list (MIN_DIS_IN,MAX_DIS_IN)+fuzz_session.Common_add_fuz
            fuzz_session.fuzz_addre_IN_REG=fuzz_ad_list (MIN_IN_REG,MAX_DIS_IN)+fuzz_session.Common_add_fuz
            fuzz_session.fuzz_addre_HO_REG=fuzz_ad_list (MIN_HO_REG,MAX_HO_REG)+fuzz_session.Common_add_fuz

            #fix for  version python  >2.7.15 ,remove dumple item
            fuzz_session.fuzz_addre_COILS=list(set(fuzz_session.fuzz_addre_COILS))            
            fuzz_session.fuzz_addre_DIS_IN=list(set(fuzz_session.fuzz_addre_DIS_IN))
            fuzz_session.fuzz_addre_IN_REG=list(set(fuzz_session.fuzz_addre_IN_REG))
            fuzz_session.fuzz_addre_HO_REG=list(set(fuzz_session.fuzz_addre_HO_REG))
            
            #sort(reverse=False)
            fuzz_session.fuzz_addre_COILS.sort(reverse=False)
            fuzz_session.fuzz_addre_DIS_IN.sort(reverse=False)
            fuzz_session.fuzz_addre_IN_REG.sort(reverse=False)
            fuzz_session.fuzz_addre_HO_REG.sort(reverse=False)

            lgr.info('')
            lgr.info('-------------------------- Configuration a probability of applying the fuzz categories ---------------------------')                  
            lgr.info('prob_list  : %s'%prob_list)                          
            lgr.info('')
            lgr.info('-------------------------- Configuration Read from CSV  -----------------------------------------------------------')
            lgr.info('FCmergedlist : %s'%FCmergedlist)            
            lgr.info('COILS_list   : %s' %COILS)
            lgr.info('DIS_IN_list  : %s' %DIS_IN)            
            lgr.info('HO_REG list  : %s' %HO_REG)            
            lgr.info('IN_REG_list  : %s' %IN_REG)           
            lgr.info('')
            lgr.info('---------------------------- Set Configuration --------------------------------------------------------------------')
            lgr.info('start_address READ_COILS : %d' %MIN_COILS )
            lgr.info('last_address READ_COILS : %d' %MAX_COILS )
            lgr.info('start_address READ_DISCRETE_INPUTS: %d' %MIN_DIS_IN)
            lgr.info('last_address READ_DISCRETE_INPUTS: %d' %MAX_DIS_IN)
            lgr.info('start_address READ_HOLDING_REGISTERS: %d' %MIN_HO_REG)
            lgr.info('last_address READ_HOLDING_REGISTERS: %d' %MAX_HO_REG)
            lgr.info('start_address READ_INPUT_REGISTERS: %d' %MIN_IN_REG)
            lgr.info('last_address READ_INPUT_REGISTERS: %d' %MAX_IN_REG)
            lgr.info('Number for fuzz_request for FC: %d' %fuzz_request)
            lgr.info('Fuzz address READ_COILS: %r' %fuzz_session.fuzz_addre_COILS)
            lgr.info('Fuzz address READ_DISCRETE_INPUTS: %r' %fuzz_session.fuzz_addre_DIS_IN)
            lgr.info('Fuzz address READ_INPUT_REGISTER: %r' %fuzz_session.fuzz_addre_IN_REG)
            lgr.info('Fuzz address READ_HOLDING_REGISTERS: %r' %fuzz_session.fuzz_addre_HO_REG)
            lgr.info('')
            lgr.info('----------------------------- Set Configuration Smart values and operation fuzzing -----------------------------------')
            lgr.info('Set Configuration Smart values')
            lgr.info("\n".join("('{}':{})".format(k, v) for k, v in p.dict_smart_value().items()))
            lgr.info('Set operation fuzzing')
            lgr.info("\n".join("('{}:{})".format(k, v) for k, v in p.dict_operation().items()))                    
            lgr.info('')
            lgr.info('---------------------------- Set Configuration for function 20,21,22 ----------------------------------------------\n')
            lgr.info('start_address start_address_records : %d' %start_address_reco )
            lgr.info('last_address last_address_records : %d' %last_address_reco)                               
            lgr.info('-------------------------------------------------------------------------------------------------------------------\n')

    except IOError:
            lgr.error('No such file or directory: search.csv')
            sys.exit(1)
                    

#------------------------------------------------------------
# The main fuzzer function
# set parametre host 
# start with a socket at 5-second timeout
#------------------------------------------------------------
def do_work( forever=True):
    global num_of_request,host
    
    while True:
        MAXIMUM_NUMBER_OF_ATTEMPTS=3
        lgr.info("Creating the socket")          
        master1.__init__(host=host, port=502, timeout_in_sec=1.0)

        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
            try:           
                master1.open_b()
                lgr.info('Socket connect worked!')                             
                start_fuzzer()       
                 
            #except EnvironmentError as exc:
            except socket.error:
                lgr.error('Socket connect failed! Loop up and try socket again')               
                time.sleep( 5.0)
                continue
        else :
            lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)            
            lgr.info("Fuzzer terminate !!.")
            master1.close()
            sys.exit(1)

#---------------------------------------------------------------------------------- 
#Initializing Fuzzer started, 
#int smart_value and fuzz_operation (p.int_smart_value,p.int_fuzz_operation() 
#-----------------------------------------------------------------------------------         
def start_fuzzer():
    global running,fuzz_mode,search_mode,start_time,end_time,num_of_request,pcap_mode
    start_time = datetime.now()                             #start time for duration time      
    lgr.info('Initializing fuzz log reader ')
    lgr.info('Fuzzer started ')
    p=dict_fuzz_object()
    p.int_smart_value()
    p.int_fuzz_operation()
    
    # phase I Search FC and address
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode==False:
            lgr.info('Running  in Search_mode True!')
            b_box=black_box()                                #object for scan  function support ans map address
            b_box.con_SUT()                                  #run test black box                                  
            info(start_time,fuzz_session.num_of_request)     #info time and request 
            sys.exit(1)                                        
            
    elif  fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode== True :
            lgr.info('Running  in Search_mode True and pcap_mode!')
            b_box=black_box()                                #object for scan  function support ans map address            
            b_box.con_SUT_pcap()                             #read pcap file and add info in csv file          
            info(start_time,fuzz_session.num_of_request)
            sys.exit(1)   

    elif  fuzz_session.search_mode==False and fuzz_session.fuzz_mode==True and fuzz_session.pcap_mode== False:      
            """fuzzer operation querie, search_mode False from command line param"""

            lgr.info('Running in fuzzing_mode,search_mode False and  fuzz_mode True ! ');
            Read_CSvFile()                                     #read file csv and append list for configuration          
            s=SetupAndTeardown()                               #object for fuzzer            
            s.con()                        
            info(start_time,fuzz_session.num_of_request)       #info time and request             
            sys.exit(1)                                       
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==False:
            lgr.info('Running in search mode and fuzzing mode')
            
            """run test black box """            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False          
            b_box=black_box()                                  #object for scan  function support ans map address
            b_box.con_SUT()                                    #run test black box 
            
            """run fuzzer mode and read csvFile"""
            fuzz_session.search_mode=False
            fuzz_session.fuzz_mode=True            
            Read_CSvFile()                                     #read file csv and append list for configuration
            s=SetupAndTeardown()                               #object for fuzzer            
            s.con()                                            #fuzzer querie 
            info(start_time,fuzz_session.num_of_request)       #info time and request 
            sys.exit(1) 
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==True :
            lgr.info('Running in search mode and fuzzing mode on pcap file')
            
            """run read from pcap file """            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False                       
            lgr.info('Running  in Search_mode True and pcap_mode!')
            b_box=black_box()                                 #object for scan  function support ans map address            
            b_box.con_SUT_pcap()                              #read pcap file and add info in csv file 
                                      
            """run fuzzer mode and read csvFile"""
            fuzz_session.fuzz_mode=True            
            fuzz_session.search_mode=False
            fuzz_session.pcap_mode=False
            Read_CSvFile()                                    #read file csv and append list for configuration
            s=SetupAndTeardown()                              #object for fuzzer           
            s.con()                                           #fuzzer querie 
            info(start_time,fuzz_session.num_of_request)      #info time and request 
            sys.exit(1) 

    else :
            lgr.info('search_mode none/fuzz_mode None!')
        
def print_usage():
      print(sys.argv[0], '-i <host>  -s <search_mode> -z <fuzz_mode> -f <csvFile=search.csv> -p <pcap_file=packets.pcap> -r <fuzz_request>')   

#------------------------------------------------------------------------------------------------------
# The main function, reads the fuzzer arguments and starts the fuzzer
# Defaults number of request for each FC fuzz_request=200, or  -r <fuzz_request>'fuzz_request = int(a) 
# create a directory if it does not exist, log_dir=./log 
# Counter number of request for each FC - fuzz_session.num_of_fc=fuzz_request
# fuzz_session.count_num_of_fc=fuzz_request 
#-----------------------------------------------------------------------------------------------------
def main():
   global host,log_file,fuzz_mode,search_mode,csvFile,filename,pcap_file,fuzz_request,pcap_mode,log_dir
   opts, args = getopt.getopt(sys.argv[1:], 'i:se:ze:pe:fe:r:')
   
   for o, a in opts:
      print(o, a)
      if o == '-i':
         host = a
      
      elif o == '-s':
         fuzz_session.search_mode = True

      elif o == '-p':
         #host = a 
         pcap_file="packets.pcap"            
         fuzz_session.pcap_mode = True
                                                           
      elif o == '-f':
         csvFile="search.csv"                                         #defaults   
                    
      elif o == '-z':
         fuzz_session.fuzz_mode = True

      elif o == '-r':                                  
         fuzz_request = int(a)                                        #define request for each FC
                                                                
      else: 
         assert False, "unhandled option"                        

   fuzz_session.num_of_fc=fuzz_request
   fuzz_session.count_num_of_fc=fuzz_request 
   lgr.info('SUT Unit IP address : ' + host )                          #ip address SUT  
   lgr.info('log_file : ' + filename1 + filename2 )
   lgr.info('csvFile : ' + log_dir + csvFile)                          #file name auto for logger
   lgr.info('pcap_file: ' + log_dir + pcap_file) 
   lgr.info('fuzz_request for each FC: %d',fuzz_request)
                                   
   if (pcap_file != "" and csvFile != ""):      
      start_fuzzer() 

   elif(host is None  or csvFile == ""):
      print_usage()
      sys.exit(0)
   
   elif (fuzz_session.search_mode==False and fuzz_session.fuzz_mode==False):
      print_usage() 
      sys.exit(0)        
   do_work(True)
   
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    Cleaning_up()                                                     #Cleaning up  log files 
    master1 = modbus_tcp_b.TcpMaster_b()           
    log_info(lgr,logger) 
    main()

    
    
    
    
    
