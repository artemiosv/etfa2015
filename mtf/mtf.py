#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 

 This is distributed under GNU LGPL license, see license.txt
"""
import getopt
import traceback
import math
import sys
import operator
#from dpkt import *
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
from itertools import izip_longest 

import itertools
from math import ceil
from hashlib import sha256
import csv
import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.all import *

from modlib import *
#from modbus_tk.utils import *
from struct import *
import modbus_tk.utils 

#New import 
import modbus_tcp_b 
import modbus_b 
from utils_b import *

#library from pymodbus
from message import *

import fuzz_session

#

############The RotatingFileHandler ########################################################
from logging.handlers import RotatingFileHandler
##############################################################################################

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

#------------------------------------------------------------------------------------------------------------------
# pdu sruct.pack for fc support mobdus_tk
#--READ_COILS,READ_DISCRETE_INPUTS,READ_HOLDING_REGISTERS,READ_INPUT_REGISTERS 
#pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)-

#--(WRITE_SINGLE_COIL,WRITE_SINGLE_REGISTER)
#pdu = struct.pack(">BHH", function_code, starting_address, output_value)-

#----(WRITE_MULTIPLE_REGISTERS,WRITE_MULTIPLE_COILS)
#pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count) 
#------------------------------------------------------------------------------------------------------------------


#supported modbus_tk functions (8)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_COILS = 15
WRITE_MULTIPLE_REGISTERS = 16 

# add extra function for fuzzer -insert from pymodbus 1.2.0 (module:file_message.py)
#Encapsulated Interface Transport=43       (0x2B) MEI_sub_function_code  13/14
Read_device_Identification=43

Read_Write_Multiple_Registers=23           #(0x17)   
Mask_Write_Register=22                     #(0x16)
 
#File record access  
Read_FIFO_queue =24                        #(0x18)
Read_File_record =20                        #(0x14) 
Write_File_record =21                       #(0x15)  

#Report_Slave_ID =17                       #(0x11) (Serial Line only)


#modbus exception codes  support modbus_tk/
ILLEGAL_FUNCTION = 1
ILLEGAL_DATA_ADDRESS = 2
ILLEGAL_DATA_VALUE = 3
SLAVE_DEVICE_FAILURE = 4
SLAVE_DEVICE_BUSY = 6
MEMORY_PARITY_ERROR = 8
ACKNOWLEDGE = 5
NEGATIVE_ACKNOWLEDGE = 7
GATEWAY_PATH_UNAVAILABLE = 10
GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 11

#supported block types
'''COILS = 1
   DISCRETE_INPUTS = 2
   HOLDING_REGISTERS = 3
   ANALOG_INPUTS = 4
'''
#define for search mapping block/for black-box
s_address=0
l_address=65535
offset_address=65535                       # poso tha metakinitho apo thn arxi
step=32768                                 # step for search memory map
fix_step=250                               # fix step for search map /def chk_list
 

 #list of supported address   
supported_address_coil = []
supported_address_input_reg = []
supported_address_dist_input = []
supported_address_hold_reg = []

#list of not response address 
not_response_address_coil = []
not_response_address_input_reg = []
not_response_address_dist_input = []
not_response_address_hold_reg = []


#define for function add block/fuzzing 
slave=1
start_address=0
last_address=40000
size_of_bank=9999
offset_fuzzer=0                             # up - down bank memory 
name_of_block=None
value_range=64                              # quantity_of_x how value read 
mem_step=1024                               # how match move to memory -step
FCmergedlist=[]                             #list fc for merge csv config file


#set step for read block memory with memory dump attack
scv_table='dump_memory.csv'
quantity=100
step_mem_dump=100



#Time setting for duration
start_time=0
end_time=0

#list of fuzz address/
Common_add_fuz=[0,1,2,65535,65534,65533]    #list of common fuzzing address


""" Total number of reguest """
num_of_reguest=0


"""Def number of reguest for each FC """
fuzz_reguest=200                        

""" Define value for MIN MAX Address of bank """
MIN_COILS=0
MAX_COILS=0
MIN_IN_REG=0
MAX_IN_REG=0
MIN_DIS_IN=0
MAX_DIS_IN=0
MIN_HO_REG=0
MAX_HO_REG=0

#define for function 20,21,22
start_address_reco=0
last_address_reco=9999                           # Each file contains 10000 records, addressed 0000 to 9999 
offset_fuzzer_reco=128 
mem_step_reco=64 



"""list for fuzzing"""
foo_value= [0,65535]
foo_qua= [1,0,125]
foo_fct= [0,127,17,43,11,12,8,24,20,21,23]        #include some valid public code for serial

#global flag_pdu
flag_pdu=0                                        #fuzz pdu send response
nu_reg=1                                          # fuzz write multicoil/register /value

"""Use to Invalid_quantity"""
qua_IN_REG_HO_REG=[0,1,2,3,63,123,124,125,126,127,65333,65534,65535]         #Quantity   1 to 125 (0x7D)
qua_COILS_DIS_IN=[0,1,2,3,1000,1998,1999,2000,2001,2002,65333,65534,65535]   #Registers  1 to 2000 (0x7D) 
# contiguous registers (1 to  123  registers) for 16 (0x10)/

"""23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121"""
qua_WR_MU_REG_RW_Multiple=[0,1,2,3,119,120,121,122,123,124,125,126,127,60,61,62,65333,65534,65535]
qua_W_MUL_COILS =[0,1,2,3,984,1966,1967,1968,1999,2000,65333,65534,65535]

#Quantity  to Write  =121 /fuzze field value
value_w_fc23= [0,1,2,60,119,120,122,123,121,65533,65534,65535] 

"""Invalid_trans_IDs"""
flag_IDs =1                                                           #  def TransIdIs /invalid trans id


""" 20 (0x14) Read File Record flag for fuzzer pdu/and dumple pdu"""
R_Type=[0,1,2,3,4,5,7,8,9,10,11,12]                                    #Reference Type list
foo_len_rec=[0,1,2,3,4,5,6,246,247,248,249,250,251,252,253,254,255]    # normal x07 to 0xF5 /7-245 /one BYTES 
flag_File_record=1
nu_File_record_WRITE=1
#pdu dumple 
n_rep_ranbyte=1
n_rep_ranbit=1
z=7                                    
n_rep_pdu=0 
y=1
C=1 

"""Random Binary List"""
randBinList = lambda n: [randint(0,1) for b in range(1,n+1)]

"""ranges  of PDU :"""
#ADU 1453 +7 = 1460 B MAX ,max packet 260B
foo_len= [0, 1,2,3,4,5,6,7,8,9,10,255,256 ,257,258,259,260,261,262,263,264,1452,1451,1454,1455,1461,1462,1459,1458,65534,65533,65535]

"""FC List
Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.
User-defined codes in the ranges {65-72, 100-110} """
flag_i=0
foo_fct= [0,(7,8,9,11,12,17,43),range(65,73),range(100,110),range(111,128),range(73,80),range(1,65)]

"""List of choise fuzzer"""
fp= [ 'repeat','random_pdu','remove','message']
f_mbap=['len' ,'clone','transId', 'protoId', 'unitId', ]
payload_pdu=['diagnostics','randByte','randBit','corrupt_bytes','little_endian_payload','sendbad', 'sendresponse','exception']      

"""List for choise fuzz field pdu"""
f_reg=['function_code', 'starting_address', 'quantity_of_x']
f_wr=['function_code', 'starting_address', 'output_value']
f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
f_read_file_rec=['function_code', 'records','Byte_Count','Reference_Type']
f_write_file_rec=['function_code', 'record_data', 'Request_Data_length','record_length','Reference_Type']
f_mask=['function_code', 'and_mask','or_mask']
f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']
        
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
                (0x10, '\x10\x00\x01\x00\x02\x04\0xff\xff'),          # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' \
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x00'),                           # read device identification                       # read device identification
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

bad = (                                                        #ITEM 12  
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
        (01, '\x08\x00\x01\x00\x00'),                               #restartCommunaications
        (02, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (03, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (04, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (05, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (06, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (07, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
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
#------------------------------------------------------------
# This class about global variable mode search and fuzzing NOT USE  /Use fuzz_session.py 
#------------------------------------------------------------
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
# filtered_pcap    --trace pcap file reguest/response modbus
# mod_file_response -trace pcap file /response modbus
# mod_file_reguest  -trace pcap file reguest/modbus


#---------------------------------------------------------------------------------------------------------------------
prob_list = [('payload', 0.4), ('field_ADU', 0.1), ('field pdu', 0.3),('two fields in message', 0.1),('Not_fuzz',0.1)]

#---------------------------------------------------------------------------------------------------------------------

host=None            
log_dir = "./"                             # ./dir
csvFile= "" 
log_file="" 
pcap_file="" 
filtered_pcap="filtered.pcap"
mod_file_response='filter_resp.pcap'
mod_file_reguest='filter_reg.pcap'                     
#iface = 'eth0'


"""------------------------------------------------------------
# logs all output to a file, if no file is
# specified, it prints to standard output
#------------------------------------------------------------
"""
 # log to the console
 #console_handler = logging.StreamHandler()
 #level = logging.INFO
 #console_handler.setLevel(level)
 #logger.addHandler(console_handler)
 # create console handler and set level to debug
 #ch = logging.StreamHandler()
 #ch.setLevel(logging.INFO)
 #------------------------------------------------------------

class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Handler for logging to a set of files, which switches from one file
    to the next when the current file reaches a certain size, or at certain
    timed intervals
    """
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        # If rotation/rollover is wanted, it doesn't make sense to use another
        # mode. If for example 'w' were specified, then if there were multiple
        # runs of the calling application, the logs from previous runs would be
        # lost if the 'w' is respected, because the log file would be truncated
        # on each run.
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

###########################################################################
# create logger- - 
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('')
#lgr.disabled = True  #disable log file/
###############################################################################

#set up logging to file
def log_info(lgr,logger) :
                
    global filename1,filename2
    lgr.setLevel(logging.INFO)
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename1 = os.path.join(log_dir, 'info_%s.log' % now)
    filename2 = os.path.join(log_dir, 'error_%s.log' % now)
    # add a rotating handler
    # add a file handler/two separation file
    #fh = logging.FileHandler(filename1)
    
    fh=SizedTimedRotatingFileHandler(
    filename1, maxBytes=50*1000000, backupCount=30,                   #50mb / change
        when='s',interval=10000,
        #encoding='bz2',  # uncomment for bz2 compression
        )
    #fh = logging.handlers.RotatingFileHandler(filename1, maxBytes=500*1000000, backupCount=5)
    fh1 = logging.FileHandler(filename2)
    fh.setLevel(logging.INFO)
    fh1.setLevel(logging.WARN)
    # create a formatter and set the formatter for the handler.
    frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt)
    fh1.setFormatter(frmt)
    # add the Handler to the logger
    lgr.addHandler(fh)
    lgr.addHandler(fh1)
    logger.addHandler(fh)
    logger.addHandler(fh1)

#########################################################################

#------------------------------------------------------------
# This function print info time duration and total reguest
#------------------------------------------------------------

def info(start_time,num_of_reguest):
    #global num_of_reguest
    import fuzz_session
    end_time = datetime.now()
    lgr.info('Duration: {}'.format(end_time - start_time))
    lgr.info('Total reguest : %d', fuzz_session.num_of_reguest) 
    print('Duration: {}'.format(end_time - start_time))
    print('Total reguest : %d ' % fuzz_session.num_of_reguest)
   
#------------------------------------------------------------
# This function cleans temporary files and stop the fuzzer 
# upon Ctrl+c event
#------------------------------------------------------------
def signal_handler(signal, frame):
   lgr.info('Stopping  Ctrl+c ')
   master1.close()
   sys.exit(0)

#------------------------------------------------------------
# This function cleans temporary log files 
#------------------------------------------------------------
def Cleaning_up():   
   
   lgr.info('Cleaning up  log files')
   os.system('sudo rm -rf ' + log_dir + '*.log.*')
   os.system('sudo rm -rf ' + log_dir + '*.log')   
   

############################################################################################
 #Some format directives
    #%d decimal
    #%u unsigned decimal
    #%x hexadecimal
    #%s string
    #%n writes number of bytes printed that far
    #%c ASCII character
    #...... 
    #The %e, %f, and %g formats display floating-point numbers

    # '\0' insert string terminator
 #------------------------------------------------------------
    #create a random string in Python   

"""
HexByteConversion

Convert a byte string to it's hex representation for output or visa versa.

ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
"""

#-------------------------------------------------------------------------------

# test data - different formats but equivalent data
#__hexStr1  = "FFFFFF5F8121070C0000FFFFFFFF5F8129010B"
#__hexStr2  = "FF FF FF 5F 81 21 07 0C 00 00 FF FF FF FF 5F 81 29 01 0B"
#__byteStr = "\xFF\xFF\xFF\x5F\x81\x21\x07\x0C\x00\x00\xFF\xFF\xFF\xFF\x5F\x81\x29\x01\x0B"

#-------------------------------------------------------------------------------

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

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    #return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )                                #not space

#-------------------------------------------------------------------------------

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


# Fibonacci numbers module

def fib(n):    # write Fibonacci series up to n
    a, b = 0, 1
    while b < n:
        print b,
        a, b = b, a+b

def fib2(n): # return Fibonacci series up to n
    result = []
    a, b = 0, 1
    while b < n:
        result.append(b)
        a, b = b, a+b
    return result


def randstring(length=7):
    valid_letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join((random.choice(valid_letters) for i in xrange(length)))

        
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
def rand_XShortField():                        # rundom hex 2 bytes
  # return hex(random.randint(0,65535))  
    start = datetime.now()     
                   
    random.seed(start)
    return random.randint(0,65535)


def rand_XByteField():                        # rundom hex 1 byte
   #return hex(random.randint(0,255))
   start = datetime.now()     
                   
   random.seed(start)
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

####################################################################
## from scapy fuzzing##
####################################################################
def corrupt_bytes(s, p=0.01, n=0):
    """Corrupt a given percentage or number of bytes from a string"""
    s = array.array("B",str(s))
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i] = (s[i]+random.randint(1,255))%256
    return s.tostring()


def corrupt_bits(s, p=0.01, n=None):
    """Flip a given percentage or number of bits from a string"""
    s = array.array("B",str(s))
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i/8] ^= 1 << (i%8)
    return s.tostring()

#convert string to hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)

'''Generate random numbers using the time difference between loop
  iterations.  Quo is 'time' in Latin.'''
           
class Quo:
   
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
        '''Get truly random bytes, i.e., random bytes post hashing.'''
     
        random_bytes = []
     
        # sha256 wants a minimum input length of 32 bytes.  Since users
        # can request any byte length, round requests up to the nearest
        # 32 byte chunks.
        for i in range(int(ceil(_len / 32.0))):
          raw_bytes = self.get_raw_bytes(32)
     
          random_bytes.append(sha256(raw_bytes).digest())
     
        return ''.join(random_bytes)[:_len]
     
   
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
    li.append((last+first)/2)
    return li
             


# some def for use ,all def for fuzzer payload adu+pdu copy from unittest.py
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
        """create mbap custom"""
        mbap = modbus_tcp_b.TcpMbap_b()                            #create mbap object  custom
        mbap.transaction_id = 1
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
        for i in xrange(0, 255):
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
          mbap.length = fuzzer_ADU().Invalidlen(self)uest is build properly"""
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

#
# This Class fuzzes / verify function code and mapping address

class black_box:
    global csvHeading,list_csv,csvFile,pcap_file,filtered_pcap,csv_Heading_memory,list_of_results,rang_memory
    list_csv=[]                                                              #list of list results of search
    csvHeading= ["FC_1","FC_2","IN_REG","COILS","DIS_IN","HO_REG"]
    
    #Define for storege /memory dump attack
    csv_Heading_memory=["address_read","Value"]
    rang_memory=[]                                                  #add addres eg (0,100) as tumple/etch time
    list_of_results=[]                                                       #list of list results of search/tuples
    
    def __init__(self,csvFile='',pcap_file=""):
        self.csvFile=csvFile
        self.pcap_file=pcap_file
        self.filtered_pcap=filtered_pcap
               
    # this method write results of search black box to file csv    
    def WriteCSVFile (self,csvFile):
        global csvHeading,list_csv
       
        ofile  = open(csvFile, "wb")        
        writer = csv.writer(ofile, delimiter='\t')
        writer.writerow(csvHeading)                                   #making header here
        for values in izip_longest (*list_csv):
            writer.writerow(values)      
        ofile.close()    

    # this method write results of  memory dump attack to file csv  each table memory block     
    
    def WriteCSVblock (self,scv_table):
        
        ofile  = open(scv_table, "wb")        
        writer = csv.writer(ofile,delimiter='\t')
        #writer.writerow(csv_Heading_memory)
        for values in izip_longest (rang_memory,list_of_results):
            writer.writerow(values)                                          #making header here             
        ofile.close()  


    # this method copy for pymodbus ,test_factory.py  
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
                (0x2b, '\x2b\x0e\x01\x00'),                           # read device identification                       # read device identification
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
        (01, '\x08\x00\x01\x00\x00'),
        (02, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (03, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (04, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (05, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (06, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (07, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
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
                response_pdu=master1.execute_f(slave, READ_COILS , address_fuz, value_range)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_coil)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_INPUT_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_INPUT_REGISTERS , address_fuz, value_range)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_DISCRETE_INPUTS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_DISCRETE_INPUTS , address_fuz, value_range)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_HOLDING_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave,READ_HOLDING_REGISTERS , address_fuz, value_range)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return  list   

    #check list of support address for number of elements min 3 elements
    def chk_list_Up(self,list):
        global step,s_address,l_address
        #init_        
        s_address=fuzz_session.s_address
        l_address=fuzz_session.l_address
        step=fuzz_session.step
                                                     
        if list==supported_address_coil :
            
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                                  
                    self.scan_coil(s_address,l_address,step,list)
                    l_address=s_address+(2*step)
                                                                                                            
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    
                    if len(list) == 0 :
                        max_el=0
                    #min_el=min(list)                          #is 0 ? or not 
                    #set s_address is max item of list
                    s_address=max_el
                    #lgr.info('step: ----->%d '% step)                                     
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535              
                    #call
                    self.scan_coil(s_address,l_address,step,list)     
                                                                       
                                                                   
        elif list==supported_address_input_reg :
            
            #lgr.info('step: ----->%d '% step)
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                                   
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)
                    l_address=s_address+(2*step)                              
                
                else  :                                       #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #min_el=min(list)                          #is 0 ? or not 
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)     
                                        
                       
        elif list==supported_address_dist_input :
               
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                
                    #self.getaddress()
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)
                    l_address=s_address+(2*step)                          #call is step/2                            
                
                else  :                          #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #min_el=min(list)                          #is 0 ? or not 
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)     
                    
                     
        elif list==supported_address_hold_reg :   
            
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                
                    #self.getaddress()
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)
                    l_address=s_address+(2*step)                                                    
                
                else  :                                       #first address 0/not empty list
                    
                    #calculate max elements 
                    max_el=max(list)
                    #min_el=min(list)                          #is 0 ? or not 
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)                                    
                                          
        else :
            pass
                
        return   

    #check list of support address for number of elements min 3 elements
    def chk_list_down(self,list):
        global step,s_address,l_address
        #l_address=s_address+step
        if len(list) == 0:
            pass        
        elif min(list)!=0 :
            min_el=min(list)
            step=min_el/2
            #init value
            s_address=1
            l_address=min_el                                                           
            while step!=1 :
                step=step/2
                #lgr.info('step: ----->%d '% step)
                s_address=min(list)-(2*step)
                l_address=min(list)
                if list==supported_address_coil:
                    self.scan_coil(s_address,l_address,step,list)
                                    
                
                elif list==supported_address_dist_input :
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)
                    

                elif list==supported_address_hold_reg :
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)
                    #continue 

                elif list==supported_address_input_reg : 
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                  
                    #continue
                               
        else :
            pass        
        
        return      

    # Looking for supported function codes with wall pdu reguest
    def ReqsupportFunc(self):     

        supportedFunc = []
        
        print "Looking for supported function codes..with wall pdu reguest"
        lgr.info('\n \t  \t Looking for supported function codes..with wall pdu reguest')
        
        for func, msg in self.request:
            response_pdu=master1.execute_master(slave,msg)
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))                   
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                #print >>sys.stderr, 'returnCode is %d ' % returnCode 
                if returnCode > 127 and exceptionCode == 0x01:        #illegal function
                  #If return function code is > 128 --> error code
                  print "Function Code "+str(func)+" not supported."
                  lgr.info("Function Code "+str(func)+" not supported." )
                  
                else:
                  supportedFunc.append(func)
                  #print "Function Code "+str(func)+" is supported."
                  lgr.info("Function Code "+str(func)+" is supported." )
            else:
              print "Function Code "+str(func)+" probably supported."
              lgr.info("Function Code "+str(func)+" probably supported." )
              supportedFunc.append(func) 

        #print function list support
        print >>sys.stderr, '"\n"----------------The Function code supported / pdu search--------------' 
        self.print_results_blackbox(FC =supportedFunc)
        return supportedFunc

    # Verifies which function codes are supported by a Modbus Server-copy for modlib.py
    # Returns a list with accepted function codes
    def getSupportedFunctionCodes(self):
      
      supportedFuncCodes = []
      
      print "Looking for supported function codes (1-127) with ModbusPDU_Generic"
      lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic")
      for fct in range(0,127,1):                     
            pdu=struct.pack(">B",fct) +'\0x00\0x00'+'\0x00\0x01'
            #print >>sys.stderr, 'reguest_pdu %r ' % pdu                 
            response_pdu=master1.execute_master(slave,pdu)
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))                  
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                #print >>sys.stderr, 'The function_code is %d ' % returnCode 
                if returnCode > 127 and (exceptionCode == 0x01 or exceptionCode == 0x03):
                  # If return function code is > 128 --> error code
                  print "Function Code "+str(fct)+" not supported."
                  lgr.info("Function Code "+str(fct)+" not supported." )
                  
                else:
                  supportedFuncCodes.append(fct)
                  print "Function Code "+str(fct)+" is supported."
                  lgr.info("Function Code "+str(fct)+" is supported." )
            else:
              print "Function Code "+str(fct)+" probably supported."
              lgr.info("Function Code "+str(fct)+" probably supported." )
              #supportedFuncCodes.append(fct)                                   # not add probably supported Function Code 
      #print function list supported        
      print >>sys.stderr, '\n-----------    The Function code supported / search FC 1-127  --------------'              
      self.print_results_blackbox(FC =supportedFuncCodes)
      return supportedFuncCodes

    def getSupportedDiagnostics(self):                     # NOT USE IN TIME/RTU 

        supportedDiagnostics = []
       #if connection == None:
        #   return "Connection needs to be established first."
        print "Looking for supported diagnostics codes.."
        for i in range(0,65535):       # Total of 65535, function code 8, sub-function code is 2 bytes long
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
                print "Function Code "+str(i)+" not supported."

                
              else:
                supportedDiagnostics.append(i)
                print "Diagnostics Code "+str(i)+" is supported."
          else:
            print "Diagnostics Code "+str(i)+" probably supported."
            supportedDiagnostics.append(i)

        return supportedDiagnostics  
      
    
    # Verifies which address are supported 
    # Returns a list with accepted address
    def get_Supported(self,address_fuz,response_pdu,mylist,not_resp_list): 
        returnCode=""
        exceptionCode =""
        print >>sys.stderr, 'The response_pdu,%r'%ByteToHex(response_pdu)
        lgr.info('The response_pdu :%r'%ByteToHex(response_pdu))
        if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                print >>sys.stderr, 'The function_code is %d ' % returnCode 
                if returnCode > 127 and (exceptionCode == 0x02):  # ??
                  # If return function code is > 128 --> error code
                  print "Fuzz_address "+str(address_fuz)+" not supported."
                  lgr.info("Fuzz_address "+str(address_fuz)+" not supported." )
                 
                else:
                    if address_fuz not in mylist :                                  #if item exist in list, not append
                        mylist.append(address_fuz)
                        print "Fuzz_address  "+str(address_fuz)+" is supported."
                        lgr.info("Fuzz_address  "+str(address_fuz)+" is supported." )
                    else :
                        pass    
        else :
              print "Fuzz_address  "+str(address_fuz)+" probably supported."
              lgr.info("Fuzz_address  "+str(address_fuz)+" probably supported." )
              #add in list of support address
              mylist.append(address_fuz)
              #add in list for not support address list for use possible later
              not_resp_list.append(address_fuz)
              
        return  mylist.sort(),not_resp_list.sort()   

    """print supported address ..for data bank  - -NOT USE  IN TIME"""
    def printmap_address(self,*args):
        #print address   list supported 
        for arg in args :       
            print >>sys.stderr, '"\n"----Check for' +'%r' %arg + 'address  supported --------------'          
            print(" ".join(map(str, list)))
        return   
  
    """Check for supported address ..for data bank"""
      
    def getaddress(self):
      global step,value_range,l_address,s_address
      response_pdu=""
      ################################################################################
      print "Looking for READ_COILS, supported address .."
      lgr.info('\n \t \t Looking for READ_COILS, supported address ..')      
      #check elements of the list support address/upper 
      self.chk_list_Up(supported_address_coil)
      #if min item of list not 0
      self.chk_list_down(supported_address_coil)
      #print >>sys.stderr, '\n----Check READ_COILS, --------for address  supported --------------'          
      #print(",".join(map(str, supported_address_coil)))
      ####################################################################################
      """Check that response for read analog inputs (READ_INPUT_REGISTERS) function is ok"""
      print "Looking for READ_INPUT_REGISTERS supported address .."
      lgr.info('\n \t \t Looking for READ_INPUT_REGISTERS supported address ..')         
      self.chk_list_Up(supported_address_input_reg)      
      #if min item of list not 0
      self.chk_list_down(supported_address_input_reg)
      #####################################################################################
      """Check that response for read digital inputs function is ok""" 
      print "Looking for READ_DISCRETE_INPUTS  supported address .."
      lgr.info('\n \t \t Looking for READ_DISCRETE_INPUTS  supported address ....')      
      self.chk_list_Up(supported_address_dist_input)     
      #if min item of list not 0
      self.chk_list_down(supported_address_dist_input)
      
      ######################################################################################
      """Check that response for READ_HOLDING_REGISTERS function is ok"""  
      print "Looking for READ_HOLDING_REGISTERS  supported address .."
      lgr.info('\n \t \t Looking for READ_HOLDING_REGISTERS  supported address ..')    
      self.chk_list_Up(supported_address_hold_reg)
       #if min item of list not 0
      self.chk_list_down(supported_address_hold_reg) 
      ######################################################################################
      #print  elements of the list support address
      print >>sys.stderr, '\n-----------------    Check for address  supported    ----------------------'        
      self.print_results_blackbox(COILS =supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
      self.print_results_blackbox(NOT_RESP_COILS =not_response_address_coil,NOT_RESP_INPUT_REGISTERS=not_response_address_input_reg,NOT_RESP_DISCRETE_INPUTS=not_response_address_dist_input,NOT_RESP_HOLDING_REGISTERS=not_response_address_hold_reg)
      
      return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg 
    

    #-----------------------------------------------------------------------#
    # Read Device Information Fc =43 (0x2B) MEI_sub_function_code  13/14
    
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
    #-----------------------------------------------------------------------#

    def Read_Device_Information(self):
        '''  basic message encoding '''
        mei_object=[]                                 #list
        #params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] }  #dictionary
        #handle  = ReadDeviceInformationRequest(**params)
        print "Looking for read device information ....."
        lgr.info('\n  \t \t  Looking for FC 43 : READ Device Information (Error) SubFC :14    ')
        for read_code in range(1,5,1) :                                    # Read Device ID code
            for object_id in range(0,127,1) :
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=master1.execute_master(slave,result)
                #lgr.info('response ---> : %r ' % ByteToHex(response))
                if response:                
                    data = str(response)
                    data2 = data.encode('hex')               
                    returnCode = int(data2[0:2],16)
                    exceptionCode = int(data2[3:4],16)
                        
                    if returnCode > 127 and (exceptionCode == 0x02 or exceptionCode == 0x01 or exceptionCode == 0x03):
                          # If return function code is > 128 --> error code
                        print " exceptionCode :%r" %exceptionCode
                        lgr.info('- response :   ---> %r exceptionCode : %r  ' % (ByteToHex(response),exceptionCode))
                        continue
                         
                    else :                
                        message = response[1:len(response)]          #parse_response FC=43
                        if len(message)<6 :
                            lgr.info('response message ---> : %r' % ByteToHex(message))
                            continue
                         
                        '''read device information MESSAGE response  decode '''       
                        handle  = ReadDeviceInformationResponse()    # send to decode
                        handle.decode(message)   
                        print "Read Device ID code : %d" % handle.read_code
                        lgr.info('Read Device ID code : %d '% handle.read_code )
                        print "object_id : %d" %object_id
                        lgr.info('Read Device ID code : %d '% object_id)             
                        print "conformity : %r" %handle.conformity
                        lgr.info('Read Device ID code : %d' % handle.conformity )
                    
                        #if  Object is in list ...
                        if handle.information not in  mei_object :                
                              mei_object.append(dict(handle.information))
                else :
                    lgr.info('- response :   ---> %r ' % ByteToHex(response))
                                                  
        #for keys,values in mei_object.items():
        #print 'object_id {0} = {1}'.format(keys, values)
        print "\n Test device identification summary creation ....."
        lgr.info('\n  \t \t Test device identification summary creation .....' )        
        lgr.info("\n".join(map(str, mei_object))) 
        print("\n".join(map(str, mei_object)))         


    """print supported address ..for data bank"""
    def print_results_blackbox(self,**kwargs):

          #print function list supported         
          #print >>sys.stderr, '"\n"-----------    The function_code supported /search 1-127  --------------'          
          #print("\n".join(map(str, supportedFuncCodes)))
          #self.print_results_blackbox(FC =supportedFuncCodes)

          #print function list support  for pdu search      
          #print >>sys.stderr, '"\n"----------------The function_code supported /pdu search--------------'          
          #print("\n".join(map(str, supportedFunc)))
          #print >>sys.stderr, '\n-----------------    Check for address  supported    ----------------------' 
          print >>sys.stderr, '                                                                              '
          for name, value in kwargs.items():
            print '{0} = {1}'.format(name, value)
          print >>sys.stderr, '                                                                              '    
          return              

    # Looking for send  some pdu reguest bad,response,and exception ,and diagnostics 
    def reguest_check(self):     

        check_response1 = []
        check_response2 = []
        check_response3 = []
        check_response4 = []
        
        print '\n  send  wall  response..'
        lgr.info('\n \t \t \t .........send  wall  response..'  )
        for func, msg in self.response:
            response_pdu=master1.execute_master(slave,msg)
            check_response1.append(ByteToHex(response_pdu))
            print 'response_pdu : %r"' % ByteToHex(response_pdu)
            lgr.info('response pdu ----->:%r ' % ByteToHex(response_pdu))                  
        
        print '\n  send  reguest bad..'
        lgr.info('\n \t \t \t ------ send  reguest bad..'  )
        for func, msg in self.bad:
            response_pdu=master1.execute_master(slave,msg)
            check_response2.append(ByteToHex(response_pdu))
            print "response_pdu : %r" % ByteToHex(response_pdu)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))   
        
        print '\n \t  send  exception..'
        lgr.info('\n  \t \t \t ..........send  exception....')
        for func, msg in self.exception:
            response_pdu=master1.execute_master(slave,msg)
            check_response3.append(ByteToHex(response_pdu))
            print 'response_pdu : %r' % ByteToHex(response_pdu)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))
        
        print '\n  send  diagnostics..'
        lgr.info('\n \t \t \t ........send  diagnostics..')    
        for func, msg in self.diagnostics:
            response_pdu=master1.execute_master(slave,msg)
            check_response4.append(ByteToHex(response_pdu))
            print 'response_pdu : %r"' % ByteToHex(response_pdu)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        
        print >>sys.stderr, '\n----------------Response of reguest --------------'
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
    
    ###############################################
        FC_1  FC_2    IN_REG  COILS   DIS_IN  HO_REG
           1    20       0      0        0       0
           2    43    1024    1024    1024    1024
           3          2048            2048
           4          3072            3072      ...
       ..         ....
    ###############################################
    """    

    def con_SUT (self):
            global forever,search_mode,csvFile
            
            try:
                                                      
                """ Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False """
                print >>sys.stderr, 'Verifies which function codes are (1-127) with ModbusPDU_Generic ....'
                lgr.info('\n \t Verifies which function codes are supported  .....') 
                l1=self.getSupportedFunctionCodes()   #scan  function support
                
                #Add to clobal list the return list/list of list
                list_csv.append(l1)
              
                
                """Function send request wall pdu reguest and from response create Supported Function Codes  list""" 
                print >>sys.stderr, 'create Supported Function Codes for send request wall pdu  ....'
                lgr.info('\n \t create Supported Function Codes for send request wall pdu  .... .....') 
                self.setUp()
                l2=self.ReqsupportFunc()
                list_csv.append(l2)
                #Add to clobal list the return lists                

                """ mapping address table      """
                print >>sys.stderr, 'mapping address table ....'
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
               
                """ send reguest wall response/bad/exception """
                print >>sys.stderr, 'send reguest wall response/bad/exception ....'
                self.setUp() 
                self.reguest_check()
              
                """ search Device_Information """ 
                
                self.Read_Device_Information()

                """ Write to csv search results of blackbox """ 
                self.WriteCSVFile(csvFile)
                
                """ memory read dump attack"""
                self.memory_dump()           
                                                                               
            except modbus_b.ModbusError, ex:
               
               lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
               pass     
                             
          
            except socket.timeout:
                print 'Socket timeout, loop and try recv() again'
                lgr.error('Socket timeout, loop and try recv() again')
                time.sleep( 5.0)
                #do_work(True)                                                  
                pass    
            
            except socket.error as socketerror:
                lgr.error("Socket Error: %s ", (socketerror))
                time.sleep( 5.0)
                do_work(True)                                                     #new socket connect
            
            except:                                                                #default             
                print 'Other Socket err, exit and try creating socket again'
                lgr.error('Other Socket err, exit and try creating socket again')
                traceback.print_exc()                
                time.sleep( 5.0)
                #do_work(True)
              

            finally:
                    master1.close()                    
                    print("Finally!  search all DONE !!.")
                    lgr.info("Finally! search all DONE !!.")                    
                    
                                       
    
    ######Read csv file and memory dump attacks#####################################
    """ scv_table='dump_memory.csv'/file format/

        Address 0x    --> address and offset (eg ox for COILS) ....        
        Value READ_COILS  --> Value from address    
    #################################################################################
       "Address 0x   Value READ_COILS"  
        (1, 100)    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1....)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ....)
        ...................
        Address 3x   Value READ_INPUT_REGISTERS "   
        (1, 100)    (3333, 1, 2, 3, 0, 5, 0, 0, 0,  0, 0, 0, 0, 0, ... 0, 0, 0, 0, ..)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0,...)

        ..........................................
        ......
    ##################################################################################
    """    
    #-------------------------------------------------------------------#
    def memory_dump(self):
        global slave,rang_memory,list_of_results, quantity, scv_table,step_mem_dump

        FCValues0 = []                                             #create an empty list
        FCValues1 = []
        IN_REG=[] 
        COILS=[]
        DIS_IN =[]
        HO_REG=[]

        try :
                values = csv.reader(open('search.csv', 'rb'), delimiter='\t')
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

                

                IN_REG = filter(None,IN_REG)
                COILS = filter(None,COILS)
                DIS_IN= filter(None,DIS_IN)
                HO_REG = filter(None,HO_REG)
                            
                                
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
                                         
                                   
                ################### Search for  Read the contents of all PLC data blocks  ##############################################  
                print >>sys.stderr, 'Memory dump READ REGISTERS .... ....'
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
                        print >>sys.stderr, 'Answer >> result %s' % (result,)
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
                        #lgr.info(master1.execute_f(slave, READ_INPUT_REGISTERS , address_read , quantity_of_x))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_DISCRETE_INPUTS, address_read , quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))
                        #print >>sys.stderr, 'Answer >> result %s' % (result,)                                          
                        list_of_results.append(result,)
                     
                
                """ Test  response for read READ_INPUT_REGISTERS (READ_INPUT_REGISTERS )               
                    This function code is used to read from 1 to 125 contiguous input registers in a remote device"""
                
                
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_INPUT_REGISTERS ..(%d,%d)..offset: 3X' %(MIN_IN_REG,MAX_IN_REG))
                #offset_reg_in= 30000
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
                        print >>sys.stderr, 'Answer >> result %s' % (result,)
                        list_of_results.append(result,)                                          

                """ Test  response for read HOLDING_REGISTERS  (HOLDING_REGISTERS )               
                    This function code is used to read from 1 to 125 contiguous holding registers in a remote device"""
                    #Address 40001
                print >>sys.stderr, 'Memory dump HOLDING_REGISTERS  .... ....offset:4X'
                lgr.info('\n')
                lgr.info('\t \t Memory dump HOLDING_REGISTERS  ..(%d,%d)..offset:4X' % (MIN_HO_REG,MAX_HO_REG))
                rang_memory.append('Address 4x \t Value HOLDING_REGISTERS')
                list_of_results.append('',)
                #offset_reg= 40000
                for address_read in range (MIN_HO_REG,MAX_HO_REG ,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_HO_REG :
                            quantity=(MAX_HO_REG-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        #lgr.info(master1.execute_f(slave, READ_INPUT_REGISTERS , address_read , quantity_of_x))
                        result=master1.execute_read_memory(slave, READ_HOLDING_REGISTERS , address_read , quantity)        #tuple                

                        lgr.info('Answer >> result  %s '  % (result,))
                        print >>sys.stderr, 'Answer >> result %s' % (result,)
                        list_of_results.append(result,)     
                
                #Call function to write csv file
                self.WriteCSVblock(scv_table)

                               
        except IOError:
                print 'No such file or directory: search.csv'
                lgr.error('No such file or directory: search.csv')
                sys.exit(1)
        
        
        except :
                traceback.print_exc() 
                print 'error'
                lgr.error('error')
                pass        
                    

##########################################################################################################
# add functions for read pcap file in csv file 
##########################################################################################################
    def con_SUT_pcap (self):
            global forever,search_mode,csvFile,pcap_file,filtered_pcap,mod_file_response,mod_file_reguest
            #while True:
                
            try:
                l2=[]                                      
                """ Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False """
                print >>sys.stderr, 'Verifies which function codes are read pcap file....'
                #lgr.info('\n \t Verifies which function codes are supported  .....') 
                l1=self.get_pkt(pcap_file)             #scan  function support for pcap file 
                 
                #Add to clobal list the return list/list of list
                list_csv.append(l1)
                list_csv.append(l2)
              
               
                """ mapping address table   """   
                print >>sys.stderr, 'mapping address table ....'
                
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
               
                
                
                """ Write to csv search results of search  pcap file """ 
                self.WriteCSVFile(csvFile)
                                                                                                                                  
            
            except  (KeyboardInterrupt, SystemExit):
                print "You hit control-c"
                raise
            
            
            except Scapy_Exception as msg:
                print msg, "Scapy problem ..."
                raise    
            
            except IOError as err:
                print err.errno 
                print err.strerror
                
                
            except:                                                              #default/malformed packet
                print 'Other err,continue'
                lgr.error('Other err, continue ')
                traceback.print_exc()
                pass
                             
                
            finally:                                        
                print("Finally!  search all DONE !!.")
                lgr.info("Finally! search all DONE !!.")                    
                

###########################################################################################################
#--------------------------------------------------------------------
# This function reads a pcap file /filtered_pcap and returns a packet
# object.                                                                       #not use 
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
        print('payload strip')              
        cur_payload = pkt[TCP]         
        adu_pdu=cur_payload.payload     # prepei na anaferuo kato apo to tcp oti yparxei    
        hexdump(adu_pdu)                # tipose adu_pdu
        return adu_pdu

    ##### read packet for pcap file  and  look for supported function codes with library modbus.py #######
    def get_pkt(self,pcap_file):
        supportedFuncCodes = []
        pkt_cn=0      
        print "Looking for supported function codes (1-127) with ModbusPDU_Generic from pcap file"
        lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic from pcap file")
        
        #filter by protocol, ModbusADU
        self.filter_pcap(pcap_file)                            #save in filtered.pcap/reguest and response

        self.filter_pcap_response(filtered_pcap)                #filtered_pcap= filtered.pcap   

        pkts=rdpcap(mod_file_response)                         #parsing/ scapy library/mod_file_response=filter_resp.pcap   
        
        for pkt in pkts:
            pkt_cn +=1
            cur_payload = pkt[ModbusADU_Answer]
            pdu=cur_payload.payload           
            response_pdu=str(pdu) 
                                       
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)

                if returnCode > 127 and (exceptionCode == 0x01 or exceptionCode==0x03 )  :
                # If return function code is > 128 --> error code
                    print "Function Code "+str(returnCode )+" not supported."
                    lgr.info("Function Code "+str(returnCode )+" not supported." )                  

                elif returnCode > 127 and (exceptionCode == 0x01  or exceptionCode==0x03 or exceptionCode==0x02 or exceptionCode==0x04):
                    fcn= returnCode-128                       #exeptionCode = fc+128
                    if fcn not in supportedFuncCodes:
                        supportedFuncCodes.append(fcn)
                        print "Function Code "+str(fcn)+" is supported."
                        lgr.info("Function Code "+str(fcn)+" is supported." )                          
                
                # If return function code is < 128 --> support                              
                elif returnCode < 127 :
                    if returnCode not in supportedFuncCodes:
                        supportedFuncCodes.append(returnCode)
                        print "Function Code "+str(returnCode)+" is supported."
                        lgr.info("Function Code "+str(returnCode)+" is supported." )                

                else :
                    print "returnCode "+str(returnCode)+"and exceptionCode "+str(exceptionCode)
                    lgr.warn("returnCode "+str(returnCode )+" and exceptionCode"+str(exceptionCode))                            
            
            else:
                print "Function Code "+str(returnCode )+" probably supported."
                lgr.warn("Function Code "+str(returnCode)+" probably supported.")
        #supportedFuncCodes.append(returnCode)
        supportedFuncCodes.sort()                                   #sort list                                      
        #print function list supported 
        print "\n Total packets read -----> %d" % pkt_cn
        lgr.info('\n \t  \t Total packets read -----> %d '% pkt_cn)                   
        
        print >>sys.stderr, '\n-----------    The Function code supported --------------'              
        self.print_results_blackbox(FC =supportedFuncCodes)
        
        return supportedFuncCodes


   #filter by protocol, ModbusADU/ capture reguest and  response packet Modbus
    def filter_pcap(self,pcap_file):   
        pkts = rdpcap(pcap_file)
        ports = [502]
        print('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            ((pkt[TCP].sport in ports and pkt.getlayer(ModbusADU_Answer) is not None) or (pkt[TCP].dport in ports and pkt.getlayer(ModbusADU))))
        wrpcap('filtered.pcap', filtered)   

    #filter by protocol, ModbusADU/ capture  response packet Modbus
    def filter_pcap_response(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                #filtered_pcap=filtered.pcap
        ports = [502]
        print('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].sport in ports and pkt.getlayer(ModbusADU_Answer) is not None))
        wrpcap(mod_file_response, filtered)

    #filter by protocol, ModbusADU/ capture  reguest packet Modbus
    def filter_pcap_reguest(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                #filtered_pcap=filtered.pcap
        ports = [502]
        print('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].dport in ports and pkt.getlayer(ModbusADU) is not None))
        wrpcap(mod_file_reguest, filtered)        
    

    # from reguest pdu in pcap file /Decode reguest
    # Verifies which address are supported 
    # Returns a list with accepted address
    def getadd_pcap(self,filtered_pcap):                                        
        #list of supported address   
        supported_address_coil = []
        supported_address_input_reg = []
        supported_address_dist_input = []
        supported_address_hold_reg = []

        #filter by protocol, ModbusADU/create filtered_reguest.pcap
        self.filter_pcap_reguest(filtered_pcap) 

        print "Looking for supported address"
        lgr.info("\n \t  \t Looking for supported address")
        
  
        pkts=rdpcap(mod_file_reguest)                                    # mod_file_reguest='filter_reg.pcap'
        num_packets=len(pkts)                                  
       
        # read from pkts                
        for pkt in pkts:                                                                         
        
            try:
                cur_payload = pkt[ModbusADU]                                           #remove payload after TCP
                if cur_payload is None :   
                    print "Not payload ModbusADU"
                    continue
                r_pdu=cur_payload.payload           
                pdu=str(r_pdu) 
                #print 'from file reguest_pdu:: -----> %r '% ByteToHex(pdu)
                #lgr.info('from file reguest_pdu: ----->%r '% ByteToHex(pdu))  
#
                function_code, = struct.unpack(">B", pdu[0])                           #extract function_code from support fc
                     
                print >>sys.stderr, 'Detected function_code is %r ' % function_code 
                lgr.info('Detected function_code is % s'  % function_code)                   #return tumple

        ################################################################################################################################################################################
                if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    print >>sys.stderr, 'The read_address is %d ' % starting_address,quantity_of_x 
                    
                    #used to read from 1 to 125 contiguous input registers/starting_address+
                    if function_code == READ_INPUT_REGISTERS:
                        #add  address in list
                        supported_address_input_reg.extend(range(starting_address,starting_address+quantity_of_x))
                        print "READ_INPUT_REGISTERS address" + str(range(starting_address,starting_address+quantity_of_x)) + "is supported."
                        lgr.info("READ_INPUT_REGISTERS address " + str(range(starting_address,starting_address+quantity_of_x))+" is supported." )
                    
                    #Quantity of Registers / 1 to 125 (0x7D)
                    elif function_code == READ_HOLDING_REGISTERS: 
                        #add in address in list
                        supported_address_hold_reg.extend(range(starting_address,starting_address+quantity_of_x)) 
                        #supported_address_hold_reg.append(starting_address)
                        print "READ_HOLDING_REGISTERS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported."
                        lgr.info("READ_HOLDING_REGISTERS address  "+ str(range(starting_address,starting_address+quantity_of_x))+" is supported." )

                    # Single bit/read from 1 to 2000 contiguous status of coils /Quantity of Outputs / 8, if the remainder is different of 0 N = N+1        
                    elif function_code == READ_COILS: 
                        #add in address in list
                        #byte_count = quantity_of_x / 8  if (quantity_of_x % 8) > 0:
                        supported_address_coil.extend(range(starting_address,starting_address+quantity_of_x))
                        print "READ_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported."
                        lgr.info("READ_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )


                    elif function_code == READ_DISCRETE_INPUTS: 
                        #add in address in list
                        supported_address_dist_input.extend(range(starting_address,starting_address+quantity_of_x))
                        print "READ_DISCRETE_INPUTS address  "+range(starting_address,starting_address+quantity_of_x)+" is supported."
                        lgr.info("READ_DISCRETE_INPUTS address  "+range(starting_address,starting_address+quantity_of_x)+" is supported." )
                    
                    else :
                        pass    

            #################################################################################################################
                elif function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    
                    if function_code == WRITE_SINGLE_COIL :
                        #add in address in list
                        supported_address_coil.append(starting_address)
                        print "WRITE_SINGLE_COIL address  "+str(starting_address)+" is supported."
                        lgr.info("WRITE_SINGLE_COIL address  "+str(starting_address)+" is supported." ) 


                    elif function_code == WRITE_SINGLE_REGISTER:
                        # add in address in list
                        supported_address_hold_reg.append(starting_address)
                        print "WRITE_SINGLE_REGISTER address  "+str(starting_address)+" is supported."
                        lgr.info("WRITE_SINGLE_REGISTER address  "+str(starting_address)+" is supported." )     
                
    ##############################################################################################################
                elif function_code == WRITE_MULTIPLE_REGISTERS  :

                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    print >>sys.stderr, 'write_address is %d ' % starting_address,

                    if function_code == WRITE_MULTIPLE_REGISTERS :
                        #add in address in list
                        supported_address_hold_reg.extend(range(starting_address,starting_address+quantity_of_x))        #calculate quantity_of_x 
                        print "WRITE_MULTIPLE_REGISTERS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported."
                        lgr.info("WRITE_MULTIPLE_REGISTERS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )


                    elif function_code == WRITE_MULTIPLE_COILS:
                         #add in address in list
                        supported_address_coil.extend(range(starting_address,starting_address+quantity_of_x))     #calculate quantity_of_x 
                        #add    starting_address + quantity_of_x
                        print "WRITE_MULTIPLE_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported."
                        lgr.info("WRITE_MULTIPLE_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )

    ##############################################################################################################
                
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
                    print "Mask Write Register address  "+str(starting_address)+" is supported."
                    lgr.info("Mask Write Register address  "+str(starting_address)+" is supported." )


                #24 (0x18) Read FIFO Queue--ok"""
                elif function_code == Read_FIFO_queue :
                    starting_address,=struct.unpack(">H", pdu[1:3])
                    supported_address_hold_reg.append(starting_address)
                    print "Read_FIFO_queue address  "+str(starting_address)+" is supported."
                    lgr.info("Read_FIFO_queue address  "+str(starting_address)+" is supported." ) 
                    

                # 23 /( 0x17) Read_Write_Multiple_Registers -ok"""
                elif function_code == Read_Write_Multiple_Registers  :
                    #Decode reguest 
                    read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
                    #calculate read_count/write_count
                    supported_address_hold_reg.extend(range(read_address,read_address+read_count))                                 
                    print "Read_Multiple_Registers address  "+str(range(read_address,read_address+read_count))+" is supported."
                    lgr.info("Read_Multiple_Registers address  "+str(range(read_address,read_address+read_count))+" is supported." ) 
                    
                    supported_address_hold_reg.extend(range(write_address,write_address+write_count)) 
                    print "Write_Multiple_Registers address  "+str(range(write_address,write_address+write_count))+" is supported."
                    lgr.info("Write_Multiple_Registers address  "+str(range(write_address,write_address+write_count))+" is supported.")            
                    

                else :
                    pass
                                
            except Scapy_Exception as msg:
                print msg, "Scapy problem!!"
                raise
            
            except:                                                              #default
                print ' err, parse packet .... '
                lgr.error('err, parse packet ..')                                  
                traceback.print_exc()
                continue                
        
            #finally :
        print "\n Total packets read -----> %d" % num_packets
        lgr.info('\n \t \t Total packets read -----> %d' % num_packets)
        
        #CALCULATE MAX MIN address for each list
        #MIN_COILS =min(supported_address_coil)
        #MAX_COILS =max(supported_address_coil)
              
        ##### remove dumplicate item ##########
        supported_address_coil = list(set(supported_address_coil))
        supported_address_input_reg = list(set(supported_address_input_reg))
        supported_address_dist_input = list(set(supported_address_dist_input))
        supported_address_hold_reg= list(set(supported_address_hold_reg))
        
        ######## Sort list ####################
        supported_address_coil.sort()
        supported_address_input_reg.sort()
        supported_address_dist_input.sort()
        supported_address_hold_reg.sort()

        print >>sys.stderr, '\n-----------------    Check for address  supported /pcap   ----------------------'        
        self.print_results_blackbox(COILS=supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
       
        return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg     
            
##############################################################################################################################################################################

#This functions fuzzes a field of pdu  (** look specif Modbus)
class fuzzer_pdu():    
    
    def __init__(self ):
        """Constructor. Set the communication settings"""         
        
        #self.fuzz_addre_COILS = fuzz_addre_COILS   
        
        pass

    # This function  invalid record_length  fc 21
    def enc_dec_reguest(self, pdu):
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
        #self.record_length   =  len(self.record_data) / 2
        #self.response_length =  len(self.record_data) + 1

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
  
        #print >>sys.stderr, 'records %r' % (self.records)
        total_length = sum((record.record_length * 2) + 7 for record in self.records)
        print total_length
        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length+1)               #fuzz record_length +1 or ?
           
            lgr.info(' record_length : %r' % (record.record_length+1))                                           
            packet += record.record_data
            #print >>sys.stderr, 'packet  %r' % (ByteToHex(packet) )
            
        return packet

    # This function  invalid rec_data   fc 21    
    def enc_dec_reguest_rec_data(self, pdu):
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
        #self.record_length   =  len(self.record_data) / 2
        #self.response_length =  len(self.record_data) + 1

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
  
        #print >>sys.stderr, 'records %r' % (self.records)
        total_length = sum((record.record_length * 2) + 7 for record in self.records)
        
        packet = struct.pack('B', total_length)
        for record in self.records:
            packet += struct.pack('>BHHH', 0x06, record.file_number,
                record.record_number, record.record_length)                                                                     
            packet += ''.join(random_bit(record.record_length))+'\xff'+'\xff'        #fuzze record data
            # ''.join(chr(random.randint(0,255)) for _ in range(random.randint(1,25))))
            lgr.info(' record_data : %r' % ByteToHex(packet))   
            #print >>sys.stderr, 'packet  %r' % (ByteToHex(packet) )
            #time.sleep(4) 
        return packet
    


    # This function  invalid Reference_Type fc 20,21/normal is 6
    #------------------------------------------------------------
    def Invalid_RType(self):
        #global R_Type=[0,1,2,3,4,5,7,8,9,10,11,12]
        if len(R_Type) == 0:              
            Reference_Type=random.randint(12,254)
        else :    
            Reference_Type=random.choice(R_Type)
            R_Type.remove(Reference_Type)
        return Reference_Type
        

    # This function  invalid fc in pdu
    #------------------------------------------------------------
    def Invalidfnc(self):
        """Invalid FC    """
        global flag_i
        # GLOBAL foo_fct= [0,(7,8,9,11,12,17,43),range(65,73),range(100,111),range(111,128),range(73,80),range(1,65]
        import fuzz_session                                                 #create list OFF FC
        if flag_i==0 :
            flag_i +=1
            for i in foo_fct:
                if type(i) == (tuple) or type(i) == (list) or type(i) == (range):
                    for j in i:
                        fuzz_session.fct.append(j)
                else:
                    fuzz_session.fct.append(i)                   
            #print fuzz_session.fct
            random_fct =fuzz_session.fct[0] 
            return  random_fct                                #Choice first elements FC                   
        else :
                                                             #l.insert(newindex, l.pop(oldindex))
            random_fct =fuzz_session.fct[0]
            fuzz_session.fct.insert(len(fuzz_session.fct)+1,fuzz_session.fct.pop(0))                   # fist item to last 
                                                                    
            return random_fct  

    def Invalidaddress(self,function_code):
        """invalid address return out upper last_address/first address ...""" 
         #Define global /Common_add_fuz=[0,1,2,65535,65534,65533]            #list of common fuzzing address
        import fuzz_session    # fuzz_addre_COILS,fuzz_addre_DIS_IN,fuzz_addre_IN_REG,fuzz_addre_HO_REG,MAX_HO_REG    
        #na valo kai epilogi na epilogi kai apo ti lista poy sto black -box den apantisan ?
              
        if function_code == READ_COILS or function_code== WRITE_SINGLE_COIL or function_code == WRITE_MULTIPLE_COILS : 
            #select first intem and rotate
            
            
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
                   
       
        
    #This function  invalid quantity len data /fc 20,21
    def Invalid_rec_len(self):                                                  
        """invalid quantity is passed"""       
        #global foo_len_rec=[0,1,2,3,4,5,6,246,247,248,249,250,251,252,253,254,255]       # normal x07 to 0xF5 /7-245 /one BYTES
        if len(foo_len_rec) == 0:                                                         #empty list   
            item=random.randint(7,244)
            return item 
        else :    
            item=random.choice(foo_len_rec)
            foo_len_rec.remove(item)
            return item        

    #This function  invalid quantity in pdu not dev /8
    def Invalid_quantity(self,function_code):
        """invalid quantity is nearest limit ,.."""        
        
        # Quantity of Registers  2 Bytes   1 to 125 (0x7D)
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) :                                                              
            random_quantity=qua_IN_REG_HO_REG[0]                                              #l.insert(newindex, l.pop(oldindex))
            qua_IN_REG_HO_REG.insert(len(qua_IN_REG_HO_REG)+1,qua_IN_REG_HO_REG.pop(0))                                         
            return random_quantity
        
        elif (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
            # Quantity of Registers  2 Bytes   1 to 2000 (0x7D)                
            random_quantity= qua_COILS_DIS_IN[0] 
            qua_COILS_DIS_IN.insert(len(qua_COILS_DIS_IN)+1,qua_COILS_DIS_IN.pop(0))                  
            return random_quantity 

        #write a block of contiguous registers (1 to  123  registers) for 16 (0x10)/
        #23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121        
        elif function_code == WRITE_MULTIPLE_REGISTERS  or function_code == Read_Write_Multiple_Registers:
            random_quantity= qua_WR_MU_REG_RW_Multiple[0] 
            qua_WR_MU_REG_RW_Multiple.insert(len(qua_WR_MU_REG_RW_Multiple)+1,qua_WR_MU_REG_RW_Multiple.pop(0))                  
            return random_quantity             
           
        elif function_code == WRITE_MULTIPLE_COILS : 
            # Quantity of Registers  2 Bytes   1 to 1968
            random_quantity= qua_W_MUL_COILS [0] 
            qua_W_MUL_COILS.insert(len(qua_W_MUL_COILS)+1,qua_W_MUL_COILS.pop(0))                
            return random_quantity                  
          
        else :
            pass    
        return   1       

    #This function  invalid output_value in pdu     
    def Invalid_output_value(self) :
        #global foo_value= [0,65535]
        while 1 :
          n=random.randint(0,65534)        
           
          if 'n' not in foo_value: 
            foo_value.append(n)
            return n 
          else :                                                 
         # send n+1 ???
            random_value = random.choice(foo_value)
            return random_value  



   #The functions below fuzz field PDU Modbus
    def fuzz_field_pdu(self,pdu):
        ########## Define global ###############################################################################
        """f_reg=['function_code', 'starting_address', 'quantity_of_x']
        f_wr=['function_code', 'starting_address', 'output_value']
        f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
        f_read_file_rec=['function_code', 'records','Byte_Count','Reference_Type']
        f_write_file_rec=['function_code', 'record_data', 'Request_Data_length','record_length','Reference_Type']
        f_mask=['function_code', 'and_mask','or_mask']
        f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']"""
        ######################################################################################################
        global nu_reg

        adu=""
       
        function_code, = struct.unpack(">B", pdu[0])                           #extract function_code from support fc
         
        print >>sys.stderr, 'The function_code is %r ' % function_code 
        lgr.info('The function_code is % s'  % function_code)                   #return tumple
        
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):  
          #starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
              starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
              field = f_reg[0]
              #l.insert(newindex, l.pop(oldindex))
              f_reg.insert(len(f_reg)+1,f_reg.pop(0))                
                 
              lgr.info('Fuzzing pdu field : %r' % field )
              
              if field == 'function_code':
                       function_code = self.Invalidfnc()        # tyxaio kodika                                  
                       pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                       lgr.info(' : %d' % function_code)
              elif field == 'starting_address':   # edo tha prepei na ypologiso oti apomemi kai na to kano tixaio                   
                       starting_address=self.Invalidaddress(function_code)                             
                       pdu = struct.pack(">BHH", function_code,starting_address, quantity_of_x)
                       lgr.info(' : %d' % starting_address)                   

              elif field == 'quantity_of_x':   # edo tha prepei na ypologiso na min / me to 8 kai pano apo 125                    
                       quantity_of_x=self.Invalid_quantity(function_code)
                       #print >>sys.stderr, ' %d ' % quantity_of_x                                        
                       pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                       lgr.info(' : %d ' % quantity_of_x )                      
              else :
                       print('error')
                       lgr.info('error')
              return adu,pdu            

        if function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
              starting_address,output_value = struct.unpack(">HH", pdu[1:5])
              field = f_wr[0]
              #l.insert(newindex, l.pop(oldindex))
              f_wr.insert(len(f_wr)+1,f_wr.pop(0))                                               
              print('Fuzzing pdu field :'+field )
              lgr.info('Fuzzing pdu : %s '% field )

              if field == 'function_code':
                       function_code = self.Invalidfnc()      # tyxaio kodika 
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.info(' : %d' % function_code)

              elif field == 'starting_address' :              # edo tha prepei na ypologiso oti apomemi kai na to kano tixaio
                       starting_address=self.Invalidaddress(function_code)
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.info(' : %d' % starting_address)

              elif field == 'output_value' :                  # edo tha prepei na ypologiso na min / me to 8 kai pano apo 125
                       output_value=self.Invalid_output_value()
                       print >>sys.stderr, 'output_value %d ' % output_value
                       #pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       pdu = struct.pack(">BH", function_code, starting_address)
                       pdu+= struct.pack("<H", output_value)                       #send little-endian
                       lgr.info(' : %d' % output_value)                 
              else :
                       print('error')
                       pass
              return  adu,pdu              

        if function_code == WRITE_MULTIPLE_REGISTERS or function_code == WRITE_MULTIPLE_COILS :
              """execute modbus function 15/16"""
              # get the starting address and the number of items from the request pdu
              starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
              output_value=pdu[7:]                            #register value or coil value first message             
              field = f_mul_coil_reg[0]
              #l.insert(newindex, l.pop(oldindex))
              f_mul_coil_reg.insert(len(f_mul_coil_reg)+1,f_mul_coil_reg.pop(0))                
                 
              print('Fuzzing pdu field : ' +field) 
              lgr.info('Fuzzing pdu: %r' % field )
             
              """New /for dive-into-python3
              #list(fib(1000))          
              #[0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987]
              # tuple(ord(c) for c in unique_characters)   ④unique_characters = {'E', 'D', 'M', 'O', 'N', 'S', 'R', 'Y'}
              #(69, 68, 77, 79, 78, 83, 82, 89) 
              #list(itertools.product('ABC', '123'))   ①
              #  [('A', '1'), ('A', '2'), ('A', '3'), 
              #   ('B', '1'), ('B', '2'), ('B', '3'), 
              #   ('C', '1'), ('C', '2'), ('C', '3')]
              #characters = tuple(ord(c) for c in 'SMEDONRY') SMEDONRY=hex ,string klp
              """                        
              list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*200, range(999), (27, ), (1, 2, 3, 4), range(4500),range(1999),range(2999)]
              #output_value= random.choice(list_of_regs)                     #add more elemennts                                 
              list_of_coils = [ (1, 0, 1, 1)*2222, (0, )*3333, (1, )*2323, [0, 1]*2199, [1]*12118, [1, 1]*2256, [1, 0, 1 ,1 , 1 ,1 ,1 ]*700, (1, 0, 0, 1), [1, 0]*11110]
              #byte_value= random.choice(list_of_coils)
              #randBitList = lambda n: [randint(0,1) for b in range(1,n+1)]               #Random bit List 
              randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List 
              #byte_value=randByteList(1000)                                                                
              
              if  field== 'function_code' :
                  function_code = self.Invalidfnc()                             # tyxaio fc
                  lgr.info(' : %d' % function_code) 
                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                                                            
                  pdu += output_value                                   

              elif field == 'starting_address':   # edo tha prepei na ypologiso oti apomemi kai na to kano tixaio
                  starting_address=self.Invalidaddress(function_code)                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)
                  lgr.info(' : %d' % starting_address)                  
                  pdu += output_value

              elif field == 'quantity_of_x':  
                #  quantity_of_x  - max size 123 register in one read, max allow coils 1968
                  if function_code==WRITE_MULTIPLE_REGISTERS  :             
                        quantity_of_x=self.Invalid_quantity(function_code)
                        lgr.info(' : %d' % quantity_of_x)
                        
                  else :                                          #WRITE_MULTIPLE_COILS 
                        quantity_of_x= self.Invalid_quantity(function_code)
                        lgr.info(' : %d' % quantity_of_x)
                        
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                  
                  pdu += output_value                                                 

              elif field == 'byte_count':                               # number data bytes to follow len(output_value) / 8  ,2 * len(output_value)                  
                    byte_count=  rand_XByteField()                      # to ypologizi apo thn output_value  
                    lgr.info(' : %d' % byte_count )                                                                   
                    pdu = struct.pack(">BHHB", function_code, starting_address,  quantity_of_x, byte_count)
                    pdu += output_value                                                                                                             

              elif field == 'value':
                    pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)
                    
                    #print >>sys.stderr, 'output_value %d ' % output_value 
                    if function_code==WRITE_MULTIPLE_REGISTERS : 
                      output_value= randByteList(123+len(pdu)*nu_reg)            #  eg (69, 68, 77, 79, 78, 83, 82, 89 ..)
                      lgr.info(' : %r' % (output_value,))
                      nu_reg += 2
                      for j in output_value :
                        pdu += struct.pack(">H", j)
                                          
                    else : 
                      byte_value=''.join(chr(random.randint(0,255)) for _ in range(255+len(pdu)*nu_reg)) + '\xff' + '\xff'             #WRITE_MULTIPLE_COILS max 256 = len pdu                      
                      lgr.info(' : %r' % ByteToHex(byte_value))#for i in byte_value : / #    pdu +=struct.pack(">B",i)                                                      
                      nu_reg += 3
                      pdu += byte_value

              else :
                   print('error')
                   pass
              return  adu,pdu     

        """Read_File_record  FC 20  """ 
        #Byte_Count, = pdu[1,2]
        Byte_Count, = struct.unpack(">B", pdu[1])
        Reference_Type,= struct.unpack(">B", pdu[2])  
        message = pdu[3:]                                                         #extract byte count and records ... 
 
        if function_code == Read_File_record :
            
            global y
            global flag_File_record                                                                                             # pose fores tha epanalavo ta yfistamena records
            #flag_File_record=int(math.pow(2, y))                                 # equivalent to x ^ y (ayXano geometrika)            
            field = f_read_file_rec[0]                                            #'file_number','record_length','record_length'])          
            #l.insert(newindex, l.pop(oldindex))
            f_read_file_rec.insert(len(f_read_file_rec)+1,f_read_file_rec.pop(0)) 
            print('Fuzzing pdu Read_File_record ' + field)
            lgr.info('Fuzzing pdu Read_File_record  :  '+ field )
                            
            if  field== 'function_code' :
                function_code = self.Invalidfnc()                                    # tyxaio fc                                                                                                                                      
                lgr.info(' : %r' % (function_code,))
                pdu  = struct.pack(">BBB",function_code,Byte_Count,Reference_Type)   # insert fuzz fc
                pdu += message
                
            elif field== 'records' : 
                flag_File_record += 1                
                pdu  = struct.pack(">BBB",Read_File_record,Byte_Count,Reference_Type)
                pdu += (flag_File_record*message)
                lgr.info(' : %r' % (ByteToHex(flag_File_record*message)))                                                                                       
               
            elif field== 'Byte_Count' : 
                Byte_Count= self.Invalid_rec_len()                                   #normal x07 to 0xF5 /7-245 one BYTES
                lgr.info(' : %d' % Byte_Count)
                pdu  = struct.pack(">BBB",Read_File_record,Byte_Count,Reference_Type)
                pdu += message                                                 
                
            elif field== 'record_length' :
                #USE FUZZING in loop reguest
                pass
            elif field== 'Reference_Type' :                                          #for first group choise Reference_Type                      
                Reference_Type=self.Invalid_RType()                                  #boundary rangs 0,1,2,3,4,5,7,9,10
                lgr.info(' : %d' % Reference_Type)
                pdu  = struct.pack(">BBB",Read_File_record,Byte_Count,Reference_Type)
                pdu += message
            else :
                pass    
              
            return  adu,pdu 
   

        """ Write File Record  fc 21"""  
        if function_code == Write_File_record :                                                                  
              #nu_File_record_WRITE=int(math.pow(2, C))                           # equivalent to x ^ y (ayXano geometrika)                                                                                  
              Request_Data_length,= struct.unpack(">B", pdu[1])
              message = pdu[2:]                                                   #extract byte count and records ... 
              message_data=pdu[10:]
                                                                                    
              #Decode reguest for fuzz
              (REF_TYPE,file_number,record_number,record_length)= struct.unpack(">BHHH", pdu[2:9])
              field = f_write_file_rec[0]              #'Request Data length','file_number','record_length','record_length'])
              #l.insert(newindex, l.pop(oldindex))
              f_write_file_rec.insert(len(f_write_file_rec)+1,f_write_file_rec.pop(0)) 
              print('Fuzzing pdu WRITE_File_record  : ' + field )
              lgr.info('Fuzzing pdu WRITE_File_record : '+ field )
                             
              if  field== 'function_code' :
                  function_code = self.Invalidfnc() 
                  lgr.info(' : %r' % (function_code,))                                # tyxaio fc                                                                  
                  pdu  = struct.pack(">BB",function_code,Request_Data_length)         # insert fuzz fc
                  pdu += message   
               
              elif field== 'Request_Data_length' : 
                  Request_Data_length= self.Invalid_rec_len()
                  lgr.info(' : %r' % (Request_Data_length))                            #normal x07 to 0xF5 /7-245 one BYTES
                  pdu  = struct.pack(">BB",function_code,Request_Data_length)     
                  pdu += message   
              
              elif field== 'Reference_Type' :                                          #for first group choise Reference_Type                      
                  Reference_Type=self.Invalid_RType()                                  #boundary rangs 0,1,2,3,4,5,7,9,10
                  lgr.info(' : %d' % Reference_Type)
                  pdu  = struct.pack(">BBBHHH",function_code,Request_Data_length,Reference_Type,file_number,record_number,record_length)                  
                  pdu += message_data    

              elif field== 'record_length' :            #fix  >> #change record_length each group
                  #record_length=rand_XShortField()      #this only first record_length /change
                  #pdu  = struct.pack(">BBBHHH",function_code,Request_Data_length,Reference_Type,file_number,record_number,record_length)
                  #pdu += message_data
                  results=self.enc_dec_reguest(pdu)
                  pdu  = struct.pack(">B",function_code) + results
                                   
              elif field== 'record_data' :          #fix    >>                      #change record_data each group                                     
                  #pdu  = struct.pack(">BB",function_code,Request_Data_length)
                  #pdu += (nu_File_record_WRITE *message)                           # repait message after byte_2 response  
                  #nu_File_record_WRITE += 1  
                  #print  nu_File_record_WRITE
                  results= self.enc_dec_reguest_rec_data(pdu)
                  pdu  = struct.pack(">B",function_code) + results                  
                                                                                              
              else :
                  pass                  
              return  adu,pdu

        """ 22 (0x16) Mask Write Register --ok"""
        if function_code == Mask_Write_Register :

            field = f_mask[0]
            #l.insert(newindex, l.pop(oldindex))
            f_mask.insert(len(f_mask)+1,f_mask.pop(0)) 

            print('Mask Write Register :')+field
            lgr.info('Mask Write Register : '+ field )
            starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
            if field == 'function_code':
                 function_code = self.Invalidfnc()                             # tyxaio kodika 
                 lgr.info(' : %d' % (function_code,))
                 pdu = struct.pack(">BHHH", function_code,starting_address, and_mask, or_mask)
            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)
                 lgr.info(' : %r' % (starting_address))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask )     

            elif field == 'or_mask' :             
                 #or_mask=Quo().get_random_bytes(2)
                 or_mask= rand_XShortField()                                         #2 byte
                 lgr.info(' : %r' % (or_mask))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask,)
            
            elif field == 'and_mask' :             
                 and_mask= rand_XShortField()                                        #
                 lgr.info(' : %r' % (and_mask))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask)                    
                 
            else :                                                   
                  pass                                                             
      
            return  adu,pdu 

        """24 (0x18) Read FIFO Queue--ok"""
        if function_code == Read_FIFO_queue :
             
            field = random.choice (['function_code', 'starting_address'])
            print('Read_FIFO_queue field : ')+field
          
            lgr.info('Fuzzing Read_FIFO_queue pdu field :  '+ field )
            starting_address,=struct.unpack(">H", pdu[1:])                  #sos return tumple
                      
            if field == 'function_code':
                 function_code = self.Invalidfnc()                          #tyxaio kodika 
                 #starting_address=struct.unpack(">H", pdu[1:])
                 pdu = struct.pack(">BH", function_code, starting_address)
                 lgr.info(' : %d' % function_code)
                 return  adu,pdu

            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)                 
                 pdu = struct.pack(">BH",function_code ,starting_address)
                 lgr.info(' : %d' % starting_address)
                 return  adu,pdu                 
            else :                                                   
                  pass
            return  adu,pdu     

        """ 23 /( 0x17) Read_Write_Multiple_Registers -ok"""
        if function_code == Read_Write_Multiple_Registers  :

            field =f_rw_reg[0]
            #l.insert(newindex, l.pop(oldindex))
            f_rw_reg.insert(len(f_rw_reg)+1,f_rw_reg.pop(0))
            print('Read_Write_Multiple_Registers :') +field
            lgr.info('Read_Write_Multiple_Registers : ' + field )
            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List 
            list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*20, range(999), (27, ), (1, 2, 3, 4), range(4500),range(1100),range(500)]
            
            #Decode reguest for fuzz
            read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
            message_data=pdu[11:]
            print >>sys.stderr, 'The read_address is %d ' % read_address
            print >>sys.stderr, 'The read_countis %d ' % read_count
            print >>sys.stderr, 'write_address %d ' % write_address      
            print >>sys.stderr, 'write_count is %d ' % write_count
            print >>sys.stderr, 'write_byte_count %d ' % write_byte_count
            
            if field == 'function_code':
                 function_code = self.Invalidfnc()
                 lgr.info(' : %d' % function_code)                                                    #random FC                                                                
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
                 pdu += message

            elif field == 'read_count' :                                                           # Quantity to Read/2 byte/ 1-125
                 read_count=self.Invalid_quantity(function_code)
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
                 lgr.info(' : %d' % read_count)
                 pdu += message
            
            elif field == 'write_count' :                                                          #Quantity to Write/2 byte /1-127       
                 write_count=self.Invalid_quantity(function_code)
                 lgr.info(' : %d' % write_count)
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
                 
            elif field == 'write_byte_count' :                                                      #1 byte     
                 write_byte_count=rand_XByteField()
                 lgr.info(' : %d' % write_byte_count)
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
                 pdu += message
            
            elif field == 'value':                                             # Quantity  to Write  1-121
                #define global value_w_fc23= [0,1,2,60,119,120,122,123,121,65533,65534,65535]                                                       
                random_value = value_w_fc23[0]
                #l.insert(newindex, l.pop(oldindex))
                value_w_fc23.insert(len(value_w_fc23)+1,value_w_fc23.pop(0))
                output_value= randByteList(random_value)                                 #  eg (69, 68, 77, 79, 78, 83, 82, 89 ..)                
                pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )                                                                
                lgr.info(' : %r' % (output_value,))
                nu_reg += 1                      
                for j in output_value :
                  pdu += struct.pack(">H", j)                       
          
            else :                                                   
                  pass                                                             
      
            return  adu,pdu                       

#This functions fuzzes a field of mbap (ADU)
class fuzzer_ADU():

    def __init__(self):
        pass

    def __len__(self):
        return 0

# This function invalid transaction_id in the mbap 
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
                  return k-last_transaction_id
        else: 
            tr_transaction= last_transaction_id-k
            if 0<tr_transaction <65534 :
                  flag_IDs -=1
                  return tr_transaction
            else : 
                  return k-last_transaction_id
           
  # This function  invalid in the mbap len
    #------------------------------------------------------------
    def Invalidlen(self,pdu):
        """invalid len is passed"""
        
        #define global foo_len= [255,256 ,257,258,259,260,261,262,263,264, 0, 1,2,3,4,5,6,7,8,9,10]                                                       
        random_len = foo_len[0]
        #l.insert(newindex, l.pop(oldindex))
        foo_len.insert(len(foo_len)+1,foo_len.pop(0))

        return random_len      
  


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
        """create mbap custom"""
        mbap1 = modbus_tcp_b.TcpMbap_b()                              #create mbap object  custom
        mbap1.transaction_id = 1
        mbap1.protocol_id = rand_XShortField()
        mbap1.length = rand_XShortField()
        mbap1.unit_id = 0 
        return mbap1                  
    
    def fuzz_field_mbap(self,pdu,slave):
       # is define /f_mbap=['transId', 'protoId', 'unitId', 'len' ,'clone']
       query = modbus_tcp_b.TcpQuery_b()
       mbap = modbus_tcp_b.TcpMbap_b()       
       field =f_mbap[0]       
       #l.insert(newindex, l.pop(oldindex)) first element go to end
       f_mbap.insert(len(f_mbap)+1,f_mbap.pop(0))                                                               
       print('fuzz_ADU field :' + field )
       lgr.info('fuzz ModbusADU /Fuzzing field: %r' %field)
      
       if field == 'transId':   
          mbap.transaction_id= fuzzer_ADU().TransIdIs()  #fuzz                            
          mbap.protocol_id = 0
          mbap.length =  len(pdu)+1
          mbap.unit_id = slave                                                    
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d' % mbap.transaction_id)          

       elif field == 'unitId':       
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0 
          mbap.length =  len(pdu)+1
          mbap.unit_id  = fuzzer_ADU().InvalidSlave()                              #fuzz  
          # edit only field fuzz , struct i format (4byte)                          
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d' % mbap.unit_id)
                      

       elif field == 'len':
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0                                                # is 0 for modbus specify
          mbap.length = fuzzer_ADU().Invalidlen(self)                         #fuzz
          mbap.unit_id  = slave
          # edit only field fuzz , struct i format (4byte)
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.info(' : %d' % mbap.length )
                                         
       elif field == 'protoId': 
          mbap.transaction_id=query.get_transaction_id_b()                  
          mbap.protocol_id = rand_XShortField()                              #random (0,65535)
          mbap.length = len(pdu)+1
          mbap.unit_id  = slave 
          # edit only field fuzz , struct i format (4byte) 
          lgr.info(' : %d' % mbap.protocol_id)  
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
           

       elif field == 'clone': 
          mbap=self.mbap_custom()                                                #clone mbap1 
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )          
          lgr.info(' : %d , %d ,%d ,%d' % (mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id))                               
          #adu=mbap1
       else:
          pass
          lgr.warn(' PASS Error')
          
       print >>sys.stderr, 'The mbap.transaction_id is %d ' % mbap.transaction_id 
       print >>sys.stderr, 'The mbap.protocol_id is %d ' % mbap.protocol_id
       print >>sys.stderr, 'The mbap.lengthis %d ' % mbap.length      
       print >>sys.stderr, 'The mbap.mbap.unit_id is %d ' % mbap.unit_id
       lgr.info('adu : %r ' % ByteToHex(adu))
       return adu




 #all def for fuzzer payload pdu copy from fuzzer10.py
class fuzzer_payload :
    
    def __init__(self):
      pass        
 
    
    
    #------------------------------------------------------------
    # This functions fuzzes a payload
    #------------------------------------------------------------
    
    def fuzz_payload(self,pdu):
       #define in start fp= [ 'repeat','remove','random_pdu','message']
       fuzz_type = fp[0]
       #l.insert(newindex, l.pop(oldindex)) first element go to end
       fp.insert(len(fp)+1,fp.pop(0)) 
       lgr.info('Fuzzing a payload : ' + fuzz_type)     
       
       adu,pdu=self.fuzz_payload_func[fuzz_type](pdu)   
       return adu,pdu
            
    #------------------------------------------------------------
    # This function removes a payload pdu from the packet -ok
    #------------------------------------------------------------
    def payload_remove(pdu):
       adu = ""
       lgr.info('Fuzzig a remove field pdu ')
       #print('Fuzzig a remove field pdu') 
       payloads_pdu = []  
       cur_payload = pdu    
       new_pdu=""
       pdu=new_pdu
       return adu,pdu
                
       
    #------------------------------------------------------------
    # This function inserts a random pdu payload in the packet -ok
    #------------------------------------------------------------
    
    def payload_random_pdu(pdu): 
       #define in global/ payload_pdu=['diagnostics','randByte','randBit','corrupt_bytes','little_endian_payload','sendbad', 'sendresponse','exception']      
       length=0 
       item=0           
       adu = ""       
       global flag_pdu,n_rep_ranbyte,n_rep_ranbit     #an tha epilego n astelno 1 pdu ;h polla 0= sen d1 pdu 1 send polla pdu       
       fuzz_random = payload_pdu[0]
       #l.insert(newindex, l.pop(oldindex))
       payload_pdu.insert(len(payload_pdu)+1,payload_pdu.pop(0)) 
       print('Fuzzig a insert random  pdu ' + fuzz_random)
       lgr.info('Fuzzig a insert random  pdu : %r ' %fuzz_random)             
             
       if fuzz_random =='little_endian_payload' :                                   
          if flag_pdu==0 :
            i=random.randint(1,12)
            item=i                                                          # thesi tou pdu                                  
            for fct,msg  in little_endian_payload:
                item -= 1
                if  item == 0 :                                
                  pdu=msg
                  flag_pdu=1
                  lgr.info(' random little_endian pdu : %r' % ByteToHex(pdu))
                  return adu,pdu                                            #breake
                else :
                  continue                 
          else :                                                             #flag_pdu==1
            item=random.randrange(1,12)
            print item                                                       #flag pdu=1 send pdu+++...                        
            for fct,msg  in little_endian_payload:                                  
                pdu+=msg
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info(' random  little_endian pdu : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue            

       if fuzz_random =='sendbad' :                                   
          if flag_pdu==0 :
            i=random.randint(1,12)
            item=i                                     # thesi tou pdu                                  
            for fct,msg  in bad:
                item -= 1
                if  item == 0 :                                
                  pdu=msg
                  flag_pdu=1
                  lgr.info(' random sendbad pdu : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                       #flag_pdu==1
            item=random.randrange(1,12)
            print item                                 #flag pdu=1 send pdu+++...                        
            for fct,msg  in bad:                                  
                pdu+=msg
                item -= 1
                if item==0 :
                   flag_pdu=0
                   lgr.info(' random sendbad pdu : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue                     

       elif fuzz_random  =='sendresponse' :            #flag pdu=0 / send 1 response pdu
          if flag_pdu==0 :
            i=random.randint(1,20)
            item=i                                       # thesi tou pdu                                  
            for fct,msg  in response:
                item -= 1
                if  item == 0 :                                
                  pdu=msg
                  flag_pdu=1
                  lgr.info(' random sendresponse pdu : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                       #flag_pdu==1
            item=random.randrange(1,20)
                                                                                
            for fct,msg  in response:                                  
                pdu+=msg                              #flag pdu=1 send pdu+++...
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info(' random  sendresponse pdu : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                          
       elif fuzz_random  =='exception' :              # send 1+ exception pdu
          if flag_pdu==0 :
            i=random.randint(1,9)
            item=i                                    # thesi tou pdu                                  
            for fct,msg  in exception:
                item -= 1
                if  item == 0 :                                
                  pdu=msg
                  flag_pdu=1
                  lgr.info(' random exception pdu : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                       #flag_pdu==1
            item=random.randrange(1,9)                 #flag pdu=1 send pdu+++...                        
            for fct,msg  in exception:                                  
                pdu+=msg
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info(' random exception pdu : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                               
       elif fuzz_random  =='diagnostics' :
          if flag_pdu==0 :
            i=random.randint(1,19)
            item=i                                          # thesi tou pdu                                  
            for fct,msg  in diagnostics:
                item -= 1
                if  item == 0 :
                  fc,sub=struct.unpack(">BH", msg[0:3])
                  data=rand_XShortField()                                
                  pdu=struct.pack(">BHH",fc,sub,data)       #fc +sub +random data (0 -ffff)
                  flag_pdu=1
                  lgr.info(' random  diagnostics pdu : %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                       #flag_pdu==1
            item=random.randrange(1,19)                #flag pdu=1 send pdu+++...                        
            for fct,msg  in diagnostics:                                  
                pdu +=msg
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info(' random  diagnostics pdu : %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                             
       elif  fuzz_random =='randByte' :                                          #send random char +2 byte   
         length = len(pdu)          
         
         #pdu= "".join(rand_ByteField() for i in range(length)) 
         #pdu=''.join(random.choice(chars) for i in range(length))
         
         #k=random.randint(1,15)                                                  #len of the MODBUS PDU   : max 253 bytes
         #randByte=int(math.pow(2, k))
         pdu =  HexToByte("00 00 FF FF") + ''.join(chr(random.randint(0,255)) for _ in range(n_rep_ranbyte*253)) + '\xff' + '\xff'
         print('random_bytes %d n_rep_ranbyte*253' % (n_rep_ranbyte*253)) 
         n_rep_ranbyte += 1
         lgr.info(' random  pdu : %r' % pdu)
         return adu,pdu                                     
  
       elif fuzz_random  =='randBit' :                                             # handle pdu bit  0-1  +2 byte          
           length=len(pdu)
           #k=random.randint(7,15)                                                #  equivalent to x ^ y (ayXano geometrika) ,256 -
           #n_rep_ranbit=int(math.pow(2, k))                                                                                   # len of the MODBUS PDU   : 253 bytes
           pdu= HexToByte("00 00 FF FF") + ''.join(random_bit(n_rep_ranbit*253))+'\xff'+'\xff'
           print('random_bit %d n_rep_ranbit*253' % (n_rep_ranbit*253))
           n_rep_ranbit += 1 
           lgr.info(' random  pdu : %r' % pdu)
           return adu,pdu
                        
       
       elif fuzz_random  =='corrupt_bytes' :
           length=len(pdu)
           n=random.randint(1,length)                                  # corrupt_bytes random 1-len(pdu)            
           pdu=corrupt_bytes(pdu, p=0.02, n=2)
           lgr.info(' random  pdu : %r' % pdu)
           return adu,pdu           
       else  :           
          pass                 
       
       print >>sys.stderr, ' pdu %r' % pdu
       lgr.info(' random  pdu : %r' % pdu)
       return adu,pdu
           
      
    #------------------------------------------------------------
    #------------------------------------------------------------
    # This function inserts a i dumple pdu payload in the packet
    #------------------------------------------------------------

    def payload_repeat(pdu):
        adu = ""
        global z,C
        global n_rep_pdu
        cur_payload = pdu                                                             # pose fores tha epanalavo ta yfistamena records
        n_rep_pdu=int(math.pow(2, z)) + C                               # equivalent to x ^ y (ayXano geometrika)
        print('Fuzzig payload_repeat , insert %d *dumple pdu' %n_rep_pdu)
        lgr.info('Fuzzig payload_repeat  ,insert %d *dumple pdu ' %n_rep_pdu )
                    
        #i=random.randint(10,1000)
        #n_rep_pdu=z+1                                               #increasing +1                                   
        
        pdu=n_rep_pdu*cur_payload                  
        z += 1 
        if z>16 :                                                   #65535 *pdu
            z=7
            C += 1
        else :
            pass               
        return adu,pdu  

    
    #  ------------------------------------------------------------
    # This function inserts a raw data after Tcp header in the packet
    # Generation inputs of Death 
    #------------------------------------------------------------
    def payload_message(pdu):

        print('Fuzzig a insert RAW data after TCP Modbus header')
        lgr.info('Fuzzig a insert RAW data after TCP Modbus header')
        adu=""
        cur_payload=pdu
        length = len(pdu)
        adu = "".join(chr(random.randint(0,255)) for i in range(7))
        pdu = "".join(chr(random.randint(0,255)) for i in range(length))              
        return adu,pdu      

    
    #------------------------------------------------------------
    # A map from payload fuzz type to payload fuzz function
    #------------------------------------------------------------
    fuzz_payload_func = {}
    fuzz_payload_func['repeat'] = payload_repeat           #dumple pdu payload in the packet -read_packet08.py
    fuzz_payload_func['remove'] = payload_remove           #removes a payload pdu from the packet-read_packet05.py-
    fuzz_payload_func['message'] = payload_message         #Fuzzig a insert RAW data after TCP header -read_packet09.py
    fuzz_payload_func['random_pdu'] = payload_random_pdu   #insert random corrupt pdu-read_packet06.py & read_packet07.py

""" Fuzzig none, original message send"""
class fuzzer_None:
    def __init__(self):
      pass       
    
    def fuzz_field_None(self,pdu):
        print('None Fuzzing ')
        #lgr.info('None Fuzzing ')
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
    # epilogi se kathe syndedria pdu na kani tyxaia fuzze 
    #------------------------------------------------------------
    def init_new_session(self,pdu,slave):
       global fuzz_session,num_of_reguest
       import fuzz_session 
       lgr.info('')
       lgr.info(' ------New reguest --------')
       #print("new reguest!")       
       seed = time.time()                                                       #seed time  
       F_session = Fuzz_session()                                               #Class in master_fuzzer 
       fuzz_session.num_of_reguest += 1                                         # + Num of reguest 
       
       F_session.fuzz = self.weighted_choice(prob_list) 
       # choose a random pdu to fuzz      
       if F_session.fuzz == 'payload':
          lgr.info('Prepare to fuzz a message payload ')
          adu,pdu=fuzzer_payload().fuzz_payload(pdu)
          return adu,pdu        
       elif F_session.fuzz == 'field_ADU':
          lgr.info('Prepare to fuzz a field in ADU')
          adu=fuzzer_ADU().fuzz_field_mbap(pdu,slave)
          return adu,pdu         
       elif F_session.fuzz == 'field pdu':
          lgr.info('Prepare fuzz a field  in PDU')
          adu,pdu=fuzzer_pdu().fuzz_field_pdu(pdu)
          return adu,pdu 
       elif F_session.fuzz == 'two fields in message':
          lgr.info('Prepare fuzz two fields in message')
          adu=fuzzer_ADU().fuzz_field_mbap(pdu,slave)                   
          adu,pdu=fuzzer_pdu().fuzz_field_pdu(pdu)          
          return adu,pdu
       elif F_session.fuzz == 'Not_fuzz':
          lgr.info('Prepare fuzz None')
          adu,pdu=fuzzer_None().fuzz_field_None(pdu)          
          return  adu,pdu
       
# tha ta perasoume se class argotera
#class testfuzzer :
def test_ReadWithWrongFunction():
        """check that an error is raised when sending a query with an invalid function code"""
        #self.assertRaises(modbus_tk.modbus.ModbusFunctionNotSupportedError, self.master.execute, 1, 55, 0, 10)
        bad_query = struct.pack(">HHHBH", 0, 0, 3 , 0, 55)        

        try:
            master1._sock.send(bad_query)
            response=master1._recv()
            # wait if not resonce ,message and return
            print >>sys.stderr, 'response %r' % response

        except modbus_tk.modbus.ModbusError, ex:
            assertEqual(ex.get_exception_code(), 1)
            return

def test_WriteSingleCoilInvalidValue():
        """Check that an error is raised when writing a coil with an invalid value"""
        bad_query = struct.pack(">HHHBBHH",0,0,6, 1, WRITE_SINGLE_COIL, 1, 1)
        
        master1.set_verbose(True)
        master1.send(bad_query)
        response = master1._recv()
        print >>sys.stderr, 'response %r' % response

        #assertEqual(response[:-2], struct.pack(">BBB", 1, modbus_tk.defines.WRITE_SINGLE_COIL+128, 3))
def test_BuildRequest():
        """Test that the response of a request is build properly"""
        query = modbus_tcp.TcpQuery()
        #random pdu in lista
        for pdu in [chr(3),"a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, 1)
            master1._sock.send(request)
            # wait for response, if not ..return not terminal script ...create later
            response = master1._recv()
            print >>sys.stderr, 'response %r' % response
                               

def test_pduRequest():            #only send funcode 
        """Check that an error when the request/malformed packet is invalid"""
        #query = Server._make_query()
        requests = (chr(3), chr(99), chr(127),"a"*127,"abcdfhnnnn")   # first byte is funcode 1-127
        for fct_pdu in requests:         
            hexdump(fct_pdu)             #hex funcode
            response=master1.execute_master(slave,fct_pdu)
            ## wait for response if not ..return..not terminal script ...create later

            #request = build_request(request_pdu, 1)

#----------------------------------------------------------------------------------------------------------
class SetupAndTeardown:
    
    """This is setup master object""" 
    def __init__(self,host="localhost", port=502, timeout_in_sec=5.0):

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
                global forever,FCmergedlist                
                t=TestQueries()
                
                while True:                                                                          

                    try:
                        """fuzzer function exec """                

                        if READ_COILS in FCmergedlist:
                            
                            """Check that read coil queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing coil read address ....'
                            lgr.info('\t Fuzzing  FC 01 : READ_COILS .... ')
                            t.test_readcoil()   
                            print("Finally! . Fuzzer read coil DONE !!.")
                            lgr.info('\t Finally!  Fuzzer READ_COILS  DONE !!.' )
                            FCmergedlist.remove(READ_COILS)
                            

                        elif READ_DISCRETE_INPUTS in FCmergedlist :       

                            """Check that ReadDiscreteInputs queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing ReadDiscreteInputs address ....'
                            lgr.info('\t Fuzzing  FC 02 : READ_DISCRETE_INPUTS.... ') 
                            t.test_ReadDiscreteInputs()
                            print("Finally! . Fuzzer ReadDiscreteInputs DONE !!.")
                            lgr.info('\t Finally!  Fuzzer READ_DISCRETE_INPUTS!!.' )
                            FCmergedlist.remove(READ_DISCRETE_INPUTS)
                           
                        elif READ_HOLDING_REGISTERS in FCmergedlist : 
                           
                            """Check that  hr queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing READ_HOLDING_REGISTERS address ....'
                            lgr.info(' \t Fuzzing  FC 03 : READ_HOLDING_REGISTERS .... ')
                            t.test_readhr()
                            print("Finally! . Fuzzer READ_HOLDING_REGISTERS DONE !!.")
                            lgr.info(' \t Finally!  Fuzzer READ_HOLDING_REGISTERS DONE !!.' )
                            FCmergedlist.remove(READ_HOLDING_REGISTERS)
 

                        elif READ_INPUT_REGISTERS  in FCmergedlist :
                                                   
                            """Check that  queries READ_INPUT_REGISTERS are handled correctly"""
                            print >>sys.stderr, 'fuzzing READ_INPUT_REGISTERS address ....'
                            lgr.info(' \t Fuzzing  FC 04 : READ_INPUT_REGISTERS... ') 
                            t.test_ReadAnalogInputs()
                            print("Finally! . Fuzzer READ_INPUT_REGISTERS DONE !!.")
                            lgr.info('\t Finally!  Fuzzer READ_INPUT_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(READ_INPUT_REGISTERS)

                              
                        elif WRITE_SINGLE_COIL in FCmergedlist :
                           
                            """Check that write coil queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing coil write address ....'
                            lgr.info('\t Fuzzing  FC 05 : WRITE_SINGLE_COIL .... ')
                            t.test_writecoil()
                            print("Finally! . Fuzzer write coil DONE !!.")
                            lgr.info('\t Finally!  Fuzzer WRITE_SINGLE_COIL  DONE !!.' )
                            FCmergedlist.remove(WRITE_SINGLE_COIL)

                        
                        elif WRITE_SINGLE_REGISTER in FCmergedlist :

                            """Check that write HOLDING_REGISTERS queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing HOLDING_REGISTERS write address ....'
                            lgr.info('\t Fuzzing  FC 06 : WRITE_SINGLE_REGISTER.... ')
                            t.test_writesingleHr()
                            print("Finally! . Fuzzer write WRITE_SINGLE_REGISTER !!.")
                            lgr.info('\t Finally!  Fuzzer WRITE_SINGLE_REGISTER  DONE !!.' )
                            FCmergedlist.remove(WRITE_SINGLE_REGISTER )


                        elif WRITE_MULTIPLE_COILS in FCmergedlist :
                     
                            """Check that write WriteMultipleCoils queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing WriteMultipleCoils write address ....'
                            lgr.info('\t Fuzzing  FC 15 : WRITE_MULTIPLE_COILS .... ')
                            t.test_WriteMultipleCoils()
                            print("Finally! . Fuzzer WriteMultipleCoils DONE !!.")
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_COILS DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_COILS)
                            
                        
                        elif WRITE_MULTIPLE_REGISTERS in FCmergedlist :

                            """Check that write WriteMultipleHr  queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing WriteMultipleHr write address ....'
                            lgr.info('\t Fuzzing  FC 16 : WRITE_MULTIPLE_REGISTERS .... ')
                            t.test_WriteMultipleHr()
                            print("Finally!  WriteMultipleHr DONE !!.")
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_REGISTERS)
                            
                      
                        #Check that an error when the request is new function from pymodbus 1.2.0                   

                        elif Read_File_record in FCmergedlist :

                            """Check that Read_File_record queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing Read_File_record address ....'
                            lgr.info('\t Fuzzing  FC 20 : Read_File_record .... ')
                            t.test_ReadFileRecordRequestEncode()
                            print("Finally! .. Fuzzer Read_File_record DONE !!.")
                            lgr.info('\t Finally!  FuzzerRead_File_record  !!.' )
                            FCmergedlist.remove(Read_File_record)
                            

                        elif Write_File_record in FCmergedlist :      

                            """Check that Write_File_record queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing Write_File_record address ....'
                            lgr.info('\t Fuzzing  FC 21 : Write_File_record .... ')
                            t.test_WriteFileRecordRequestEncode()
                            print("Finally! .. Fuzzer Write_File_record DONE !!.")
                            lgr.info('\t Finally!  Fuzzer Write_File_record   DONE !!.' )
                            FCmergedlist.remove(Write_File_record )
                            
                              
                        elif Mask_Write_Register in FCmergedlist :      

                            """Check that Mask_Write_Register queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing Mask_Write_Register address ....'
                            lgr.info('\t Fuzzing  FC 22 : Mask_Write_Register .... ')
                            t.test_MaskWriteRegisterRequestEncode()
                            print("Finally! .. Fuzzer Mask_Write_Register DONE !!.")
                            lgr.info('\t Finally!  Mask_Write_Register DONE !!.' )
                            FCmergedlist.remove(Mask_Write_Register)
                            #t.con()
                              
                        elif Read_Write_Multiple_Registers in FCmergedlist :      

                            """Check that Read_Write_Multiple_Registers are handled correctly"""
                            print >>sys.stderr, 'fuzzing Read_Write_Multiple_Registersaddress ....'
                            lgr.info('\t Fuzzing  FC 23 : Read_Write_Multiple_Registers .... ')
                            t.test_ReadWriteMultipleRegistersRequest()
                            print("Finally! . Read_Write_Multiple_Registers DONE !!.")
                            lgr.info('\t Finally!  Read_Write_Multiple_Registers !!.' )
                            FCmergedlist.remove(Read_Write_Multiple_Registers)
                  

                        elif Read_FIFO_queue in FCmergedlist :  

                            """Check that ReadFifoQueueRequestEncode queries are handled correctly"""
                            print >>sys.stderr, 'fuzzing Read_FIFO_queue  address ....'
                            lgr.info('\t Fuzzing  FC 24 : Read_FIFO_queue  .... ')
                            t.test_ReadFifoQueueRequestEncode()
                            print("Finally! . Fuzzer Read_FIFO_queue  DONE !!.")
                            lgr.info('\t Finally!  Fuzzer Read_FIFO_queue  DONE !!.')
                            FCmergedlist.remove(Read_FIFO_queue)
                           
                                         
                        else :                           
                            lgr.info('Error/Empty/not fuzzing FClist : %s' %FCmergedlist)
                            print("Error/Empty/not fuzzing FClist %s" %FCmergedlist)
                                                      
                            break
 
                                                                               
                    except modbus_b.ModbusError, ex:                           
                           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
                           pass                                                                                                                                                                                                     
                           
                    except socket.timeout:                           
                           #traceback.print_exc()
                           sys.exc_clear()
                           print 'Socket not response... loop and try recv() again'
                           lgr.error('Socket not response.... loop and try recv() again')                                                  
                           time.sleep( 5.0)                                                                                                                                                                                  
                           pass 
                                        
                    except socket.error as socketerror:           # e.g connection refuse,broken pipe,reset by peer                                                                                         
                           lgr.error("Socket Error: %s ", (socketerror))
                           time.sleep( 5.0)                     # loop and try recv() again new connection
                           do_work(True) 
                                                                                       
                    except:                                                              #default
                         
                           print 'Other  err, exit and try creating socket again'
                           lgr.error('Other  err, exit and try creating socket again')
                           traceback.print_exc()                  
                           time.sleep( 5.0)
                           pass       
                    
                    #finally:
                                                                                                                              
                print("Finally! . Fuzzer all DONE !!.")
                lgr.info("Finally! . Fuzzer all DONE !!.")
                master1.close()                                                                                                                                                                      
   
 #read  use function of modbus_tk, script modbus.py, def execute ( ......) , execute_f is similar in modbus_b.py my script

class TestQueries(SetupAndTeardown):
    global search_mode, fuzz_mode, MIN_COILS, MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG, fuzz_reguest
    #import fuzz_session
   
    """----quantity_of_x=value_range-----"""
    #value_range=1-125  
    def test_ReadAnalogInputs(self):

            value_range=random.randint(1,125)
            """Test that response for read analog inputs (READ_INPUT_REGISTERS) function is ok"""
            for a in range(fuzz_reguest):                 
                    address_fuz= random.randint(MIN_IN_REG,MAX_IN_REG)
                    quantity_of_x=random.randint(1,125)      
                    master1.execute_f(slave,READ_INPUT_REGISTERS , address_fuz , quantity_of_x)
                                                    
    def test_ReadDiscreteInputs(self):
            value_range=random.randint(1,2000)
            """Test that response for read digital inputs function is ok"""  
            for a in range(fuzz_reguest):              #how move to bank memory the fuzzer
                    address_fuz= random.randint(MIN_DIS_IN,MAX_DIS_IN)
                    master1.execute_f(slave,READ_DISCRETE_INPUTS , address_fuz , value_range)  # Quantity 0-2000/wall        
                    
    def test_WriteMultipleHr(self):
            """Check that write WRITE_MULTIPLE_REGISTERS  queries are handled correctly/contiguous registers (1 to  123  registers"""
            #values_write_hr = range(122)             
            """values_write_hr=range(123)  times strarting address_fuz kai 1,2,3,4,...120 """
            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List 
            #byte_value=randByteList(1000)  
            for a in range(fuzz_reguest):
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)                
                    master1.execute_f(slave, WRITE_MULTIPLE_REGISTERS  , address_fuz , output_value=randByteList(random.randint(1,123)))

    def test_WriteMultipleCoils(self):
            """Check that write WRITE_MULTIPLE_COILS queries are handled correctly/ max 1968 value_out"""
            #value_out tumple
            #output_value=([1]*16), [1]*16,(1, ),[0, 0, 1, 1]*8,(11,12), [0]*20,[0, 1, 0, 1]*20)
            #output_value=tuple([1]*1968)
            randBinList = lambda n: [randint(0,1) for b in range(1,n+1)]
            #byte_value=randBinList(1000)                                           
            for a in range(fuzz_reguest):  
                    address_fuz= random.randint(MIN_COILS,MAX_COILS)                    
                    master1.execute_f(slave, WRITE_MULTIPLE_COILS , address_fuz , output_value=randBinList(random.randint(8,1968)))

    def test_writesingleHr(self):
            """Check that write HOLDING_REGISTERS queries are handled correctly"""
           
            for a in range(fuzz_reguest): 
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)                               #random 0x0000 to  0xFFFF            
                    master1.execute_f(slave, WRITE_SINGLE_REGISTER , address_fuz , output_value=random.randint(0,65535))

    def test_writecoil(self):
            """Check that write one coil queries are handled correctly/Output Value  2 Bytes  0x0000 or 0xFF00"""
            for a in range(fuzz_reguest):
                                                                       
                    address_fuz= random.randint(MIN_COILS,MAX_COILS)                                   
                    master1.execute_f(slave, WRITE_SINGLE_COIL, address_fuz , output_value=random.randint(0,1))

    def test_readcoil(self):
            """Check that read coil queries are handled correctly"""
            
            for a in range(fuzz_reguest):   
                    address_fuz= random.randint(MIN_COILS,MAX_COILS)                                 
                    quantity_of_x=random.randint(1,1999)                                  #read 1-2000 coil                   
                    master1.execute_f(slave, READ_COILS, address_fuz, quantity_of_x)
                    
            
    def test_readhr(self):
            """Check that broadcast hr queries are handled correctly"""
            # used to read the contents of a contiguous block of holding registers 1-125 
            for a in range(fuzz_reguest):
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)
                    quantity_of_x=random.randint(1,125)               
                    master1.execute_f(slave,READ_HOLDING_REGISTERS, address_fuz , quantity_of_x)

    
    #-----------------------------------------------------------------------#
    # Read Fifo Queue > fc : 24 
    #-----------------------------------------------------------------------#
    def test_ReadFifoQueueRequestEncode(self):
            """Test that response for read ReadFifoQueueRequestEncode function is ok"""
            for a in range(fuzz_reguest):
            #for address_fuz in range (start_address-offset_fuzzer,last_address+offset_fuzzer,mem_step):
                    address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG) 
                    ''' Test basic bit message encoding/decoding '''
                    handle  = ReadFifoQueueRequest(address_fuz)
                    result  = struct.pack(">B",Read_FIFO_queue)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'Fuz_address %r response %r ' % (address_fuz , response)
                    lgr.info('Answer >> Fuz_address %s response %r '  % (address_fuz,response))
                    #lgr.info('Answer >> response %r' % (response, ))


     #-----------------------------------------------------------------------------------------------------#
    # Read File Record Request >fc : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
    #-----------------------------------------------------------------------------------------------------#
    def test_ReadFileRecordRequestEncode(self):
            ''' Test basic bit message encoding/decoding '''
            #for record_num in range(start_address_reco,last_address_reco+offset_fuzzer_reco,mem_step_reco) :
            for a in range(fuzz_reguest):
                record_num = random.randint(MIN_HO_REG,MAX_HO_REG)
                record1 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record2 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record3 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record4 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())            
                record5 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record6 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record7 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record8 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())          
                record9 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                record10 = FileRecord(file_number= rand_XByteField(), record_number=record_num, record_length= rand_XByteField())
                
                records = [record1,record2,record3,record4,record5,record6,record7,record8,record9,record10]
                handle  = ReadFileRecordRequest(records)
                result  = struct.pack(">B",Read_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result)
                lgr.info('Answer >> record_num %s response %s'  % (record_num,response,))
                print >>sys.stderr, 'response %r' % (response,)
                print >>sys.stderr, 'records %r response %r' % (records,response)
   

    #---------------------------------------------------------------------------------------------------------#
    # Write File Record Request >fc : 21   file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
    #----------------------------------------------------------------------------------------------------------#

    def test_WriteFileRecordRequestEncode(self):
            ''' Test basic bit message encoding/decoding '''
            for a in range(fuzz_reguest):
            #for record_num in range(start_address_reco,last_address_reco+offset_fuzzer_reco,mem_step_reco) :
                record_num= random.randint(MIN_HO_REG,MAX_HO_REG)
                record1 = FileRecord(file_number=rand_XByteField(), record_number=record_num , record_data=Quo().get_raw_bytes(random.randint(1,25)))       #length of the MODBUS PDU   : 253bytes
                record2 = FileRecord(file_number=rand_XByteField(), record_number=record_num , record_data=Quo().get_raw_bytes(random.randint(1,25)))
                record3 = FileRecord(file_number=rand_XByteField(), record_number=record_num , record_data=Quo().get_raw_bytes(random.randint(1,25))) 
                record4 = FileRecord(file_number=rand_XByteField(), record_number=record_num , record_data=Quo().get_raw_bytes(random.randint(1,25)))
                records = [record1,record2,record3,record4]
                handle  = WriteFileRecordRequest(records)
                result  = struct.pack(">B",Write_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result)
                #lgr.info('Fuzzing a xxxxxxxxx : %s, %r ') % (records, response)
                print >>sys.stderr, 'records %r response %r' % (records,response) 
                lgr.info('Answer >>  response %s'  % (response, ))

    #-----------------------------------------------------------------------------------------------------#
    # Mask Write Register Request fc:22  /param :address=0x0000, and_mask=0xffff, or_mask=0x0000
    #This function code is used to modify the contents of a specified holding register 
    #The normal response is an echo of the request. The response is returned after the register 
    #has been written
    #-----------------------------------------------------------------------------------------------------#

    def test_MaskWriteRegisterRequestEncode(self):
        and_mask= 0x0000                                               # 0x0000 to 0xFFFF random ??
        or_mask= 0xFFFF                                                # 0x0000 to 0xFFFF       
        ''' Test basic bit message encoding '''
        for a in range(fuzz_reguest):
                address_fuz= random.randint(MIN_HO_REG,MAX_HO_REG)
                and_mask= rand_XShortField()                          # 0x0000 to 0xFFFF random ??
                or_mask = rand_XShortField()                
                handle  = MaskWriteRegisterRequest(address_fuz, and_mask, or_mask)
                result  = struct.pack(">B",Mask_Write_Register)+handle.encode()
                #not fuzze but only display if response _pdu
                #response=master1.execute_f(slave,result)
                # fuzze and  display address_fuz and  response 
                response=master1.execute_fpdu(slave,result)
                lgr.info('answer >> address_fuz: %s  response: %r'  % (address_fuz,response))
                print >>sys.stderr, 'address_fuz %s  response %r' % (address_fuz,response)
    

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
        #context = MockContext(True)
        randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]             #Random byte List
        print "fuzz_reguest %d" % (fuzz_reguest) 
        #byte_value=randByteList(1000)
        for a in range(fuzz_reguest):
            address_read= random.randint(MIN_HO_REG,MAX_HO_REG)
            address_write= random.randint(MIN_HO_REG,MAX_HO_REG)               
                                   
            arguments = {
                        'read_address':  address_read, 'read_count': (random.randint(1,125)),
                        'write_address': address_write, 'write_registers':randByteList (random.randint(1,121)),    #fix later error (1-121)
                        } 
            handle  = ReadWriteMultipleRegistersRequest(**arguments)            
            result = struct.pack(">B",Read_Write_Multiple_Registers)+handle.encode()
            #not fuzze but only display if response _pdu
            #response=master1.execute_master(slave,result)
            # fuzze and  display address_fuz and  response
           
            response=master1.execute_fpdu(slave,result)
            lgr.info(' Answer >> address_fuz: %r write_address: %r response: %r' % (address_read,address_write,response))   
            print >>sys.stderr, 'address_fuz: %r write_address: %r response: %r' % (address_read,address_write,response)    

#-------------------------------------------------------------------#
#Read csv file for config  fuzzer/calc fuzz address list
#-------------------------------------------------------------------#
def Read_CSvFile():
    global start_address,last_address,mem_step,FCmergedlist,MIN_COILS,MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG 
    FCValues0 = []                                             #create an empty list
    FCValues1 = []
    IN_REG=[] 
    COILS=[]
    DIS_IN =[]
    HO_REG=[]


    try :
            values = csv.reader(open('search.csv', 'rb'), delimiter='\t')
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
            #remove all empty strings /and dumple item
            FCmergedlist = filter(None, FCmergedlist)                      
            [ FCmergedlist.pop(i) for i in range(len(FCmergedlist))[::-1] if FCmergedlist.count(FCmergedlist[i]) > 1 ]


            IN_REG = filter(None,IN_REG)
            COILS = filter(None,COILS)
            DIS_IN= filter(None,DIS_IN)
            HO_REG = filter(None,HO_REG)
                        
                            
            #convert all strings in a list to ints
            FCmergedlist = [int(i) for i in FCmergedlist]
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
                       
            
            #calculate fuzz  address for FC
            fuzz_session.fuzz_addre_COILS=fuzz_ad_list (MIN_COILS,MAX_COILS)+Common_add_fuz
            fuzz_session.fuzz_addre_DIS_IN=fuzz_ad_list (MIN_DIS_IN,MAX_DIS_IN)+Common_add_fuz
            fuzz_session.fuzz_addre_IN_REG=fuzz_ad_list (MIN_IN_REG,MAX_DIS_IN)+Common_add_fuz
            fuzz_session.fuzz_addre_HO_REG=fuzz_ad_list (MIN_HO_REG,MAX_HO_REG)+Common_add_fuz

                          
            print  FCmergedlist                   

            lgr.info('--------------------------    Configuration Read from CSV  -------------------------------------------\n')
            lgr.info('FCmergedlist : %s' %FCmergedlist)            
            lgr.info('COILS_list : %s' %COILS)
            lgr.info('DIS_IN_list : %s' %DIS_IN)            
            lgr.info('HO_REG: %s' % HO_REG)            
            lgr.info('IN_REG_list : %s' %IN_REG)           
            lgr.info('---------------------------- Set Configuration --------------------------------------------------------\n')
            lgr.info('start_address READ_COILS : %d' %MIN_COILS )
            lgr.info('last_address READ_COILS : %d' %MAX_COILS )
            lgr.info('start_address READ_DISCRETE_INPUTS: %d' %MIN_DIS_IN)
            lgr.info('last_address READ_DISCRETE_INPUTS: %d' %MAX_DIS_IN)
            lgr.info('start_address READ_HOLDING_REGISTERS: %d' %MIN_HO_REG)
            lgr.info('last_address READ_HOLDING_REGISTERS: %d' %MAX_HO_REG)
            lgr.info('start_address READ_INPUT_REGISTERS: %d' %MIN_IN_REG)
            lgr.info('last_address READ_INPUT_REGISTERS: %d' %MAX_IN_REG)
            lgr.info('Number for fuzz_reguest for FC: %d' %fuzz_reguest)
            lgr.info('---------------------------- Set Configuration for function 20,21,22 -----------------------------------\n')
            lgr.info('start_address start_address_records : %d' %start_address_reco )
            lgr.info('last_address last_address_records : %d' %last_address_reco)                    
            lgr.info('---------------------------------------------------------------------------------------------------------\n')

    except IOError:
            print 'No such file or directory: search.csv'
            lgr.error('No such file or directory: search.csv')
            sys.exit(1)
                    

#------------------------------------------------------------
# The main fuzzer function
#------------------------------------------------------------
def do_work( forever=True):
    global num_of_reguest,host
    
    while True:
        MAXIMUM_NUMBER_OF_ATTEMPTS=3
        # start with a socket at 5-second timeout
        print "Creating the socket"
        #set parametre host               
        master1.__init__(host=host, port=502, timeout_in_sec=5.0)
           
        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS): 
            
            try:           
                master1.open_b()
                print 'Socket connect worked!'
                lgr.info('Socket connect worked!')               
                start_fuzzer()       
                 
            #except EnvironmentError as exc:
            except socket.error:
                print 'Socket connect failed! Loop up and try socket again'
                lgr.error(' Socket connect failed! Loop up and try socket again')               
                time.sleep( 5.0)
                continue
        else :
            print ('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)
            lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)            
            print("Fuzzer terminate !!.")
            lgr.info("Fuzzer terminate !!.")
            master1.close()
            sys.exit(1)
           
""" Initializing Fuzzer started """
def start_fuzzer():
    global running,fuzz_mode,search_mode,start_time,end_time,num_of_reguest,pcap_mode
    start_time = datetime.now()                    #start time for duration time      
    lgr.info(' Initializing fuzz log reader ')
    lgr.info(' Fuzzer started ')
    print("Fuzzer started!")
    
    # phese I Search FC and address
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode==False:
            lgr.info(' Running  in Search_mode True!')
            print("search_mode True!")           
            b_box=black_box()                      # object for scan  function support ans map address
            b_box.con_SUT()                        #run test black box                                  
            info(start_time,num_of_reguest)        #info time and reguest 
            sys.exit(1)                                        
            
    elif  fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode== True :
            lgr.info('Running  in Search_mode True and pcap_mode!')
            print("search_mode  and pcap_mode True!")           
            b_box=black_box()                      # object for scan  function support ans map address            
            b_box.con_SUT_pcap()                   #read pcap file and add info in csv file          
            info(start_time,num_of_reguest)
            sys.exit(1)   

    elif  fuzz_session.search_mode==False and fuzz_session.fuzz_mode==True and fuzz_session.pcap_mode== False:      
            """fuzzer operation querie, search_mode False from command line param"""

            lgr.info('Running in fuzzing_mode  ')
            print("search_mode False! / fuzz_mode True !")            
            Read_CSvFile()                        #read file csv and append list for configuration          
            s=SetupAndTeardown()                  #object for fuzzer            
            s.con()                        
            info(start_time,num_of_reguest)       #info time and reguest             
            sys.exit(1)                                       
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==False:
            lgr.info('Running in search mode and fuzzing mode')
            print ("Running in search mode and fuzzing mode")
            
            """run test black box """            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
           
            b_box=black_box()                    # object for scan  function support ans map address
            b_box.con_SUT()                      #run test black box 
            
            """run fuzzer mode and read csvFile"""
            fuzz_session.search_mode=False
            fuzz_session.fuzz_mode=True            
            Read_CSvFile()                        #read file csv and append list for configuration
            s=SetupAndTeardown()                  # object for fuzzer            
            s.con()                               # fuzzer querie 
            info(start_time,num_of_reguest)       #info time and reguest 
            sys.exit(1) 
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==True :
            lgr.info('Running in search mode and fuzzing mode on pcap file')
            print ("Running in search mode and fuzzing mode on pcap file")
            
            """run read from pcap file """            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
                       
            lgr.info(' Running  in Search_mode True and pcap_mode!')
            print("search_mode  and pcap_mode True!")           
            b_box=black_box()                      # object for scan  function support ans map address            
            b_box.con_SUT_pcap()                   # read pcap file and add info in csv file 
                                      
            """run fuzzer mode and read csvFile"""
            fuzz_session.fuzz_mode=True            
            fuzz_session.search_mode=False
            fuzz_session.pcap_mode=False
            Read_CSvFile()                        #read file csv and append list for configuration
            s=SetupAndTeardown()                  # object for fuzzer           
            s.con()                               # fuzzer querie 
            info(start_time,num_of_reguest)       #info time and reguest 
            sys.exit(1) 

    else :
            print("search_mode/fuzz_mode None!")
            lgr.info(' search_mode none/fuzz_mode None!')
        
def print_usage():
      print sys.argv[0], '-i <host>  -s <search_mode> -z <fuzz_mode> -f <csvFile=search.csv> -p <pcap_file=packets.pcap> -r <fuzz_reguest>'   

#------------------------------------------------------------
# The main function, reads the fuzzer arguments and starts
# the fuzzer
#------------------------------------------------------------
def main():
   global host, log_file, fuzz_mode,search_mode,csvFile,filename,pcap_file,fuzz_reguest,pcap_mode
  
   opts, args = getopt.getopt(sys.argv[1:], 'i:se:ze:pe:fe:r:')
   for o, a in opts:
      print o, a
      if o == '-i':
         host = a
      
      elif o == '-s':
         fuzz_session.search_mode = True

      elif o == '-p':
         #host = a 
         pcap_file="packets.pcap"            # def
         fuzz_session.pcap_mode = True
                                  
                         
      elif o == '-f':
         csvFile="search.csv"                # def   
                    
      elif o == '-z':
         fuzz_session.fuzz_mode = True

      elif o == '-r':         
         ##Defaults number of reguest for each FC ##
         """fuzz_reguest=200 """                       
         #define reguest for each FC """
         fuzz_reguest = int(a)   
      
      else: 
         assert False, "unhandled option"   
                      

   lgr.info('SUT Unit IP address : ' + host )                         #ip address SUT  
   lgr.info('log_file : ' + filename1 + filename2 )
   lgr.info('csvFile : ' + log_dir + csvFile)                         #file name auto for logger
   lgr.info('pcap_file: ' + log_dir + pcap_file) 
   lgr.info('fuzz_reguest for each FC: %d', fuzz_reguest)    
   
  
   if (pcap_file != "" and csvFile != ""):
      start_fuzzer() 

   elif(host is None  or csvFile == ""):
      print_usage()
      sys.exit(0)
   
   elif (fuzz_session.search_mode==False and fuzz_session.fuzz_mode==False):
      print_usage() 
      sys.exit(0)        


   do_work(True)
   
#   ----------------------------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    Cleaning_up()                                             # Cleaning up  log files 
    master1 = modbus_tcp_b.TcpMaster_b()           
    log_info(lgr,logger)
#  -------------------------------------------------------------
    main() 
    
    
    
    
    
