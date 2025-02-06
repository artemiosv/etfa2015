#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2015
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
import decimal
import modbus_tk
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.hooks as hooks
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import traceback,getopt
import sys,csv, math
import operator,os
import signal
import logging.handlers as handlers
import itertools
import fuzz_session

from struct import *
from time import *
from datetime import datetime
from random import *
from modbus_tk.utils import threadsafe_function, flush_socket, to_data
from itertools import zip_longest 
from math import ceil
from hashlib import sha256

import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.all import *
from scapy.contrib.modbus import * 
from scapy.utils import warning,get_temp_file,PcapReader,wrpcap                 
from struct import *

from utils_b import *
from defines import *

from message import *  #library from pymodbus software
from coloredlogs import ColoredFormatter #coloredlogs package enables colored terminal output for Python’s logging module. 
from logging.handlers import RotatingFileHandler
from functools import reduce

import basetest 
from add_method  import ByteToHex,rand_XShortField,random_bit,random_id,rand_binary,rand_ShortEnumField,randstring,fib2, rand_XByteField,rand_ByteEnumField, rand_FieldLenField,rand_ByteField,rand_IntEnumField,rand_StrLenField


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


#------------------------------------------------------------
# The  fuzzer function, if Connection lost re-connecting 
# start with a socket at 5-second timeout
#------------------------------------------------------------

class reconnect() :
	
    def recon_do_work(self,ever=True) :
      global host
               
      MAXIMUM_NUMBER_OF_ATTEMPTS=3                        
      lgr.info("Creating the socket reconnect")
      fuzz_session.master1.__init__(host=host, port=502, timeout_in_sec=1.0)

      for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
          
          try:           
              fuzz_session.master1.open_b()
              lgr.info('')
              lgr.info('\t Socket connect worked!')
              break                             
               
          #except EnvironmentError as exc:
          except socket.error:
              lgr.error(' Socket connect failed! Loop up and try socket again')               
              time.sleep( 1.0)
              continue
      else :
          lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)            
          lgr.info("Fuzzer terminate !!.")
          fuzz_session.master1.close()
          sys.exit(1)

#------------------------------------------------------------------
# This class about global variable mode search and fuzzing NOT USE  
# Use fuzz_session.py 
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
#------------------------------------------------------------
class Fuzz_session:
  fuzz = None
 
prob_list = [('payload', 0.3), ('field_ADU', 0.1), ('field pdu', 0.3),('two fields in message', 0.2),('Not_fuzz',0.1)]

# And with import defin...py
host=None            
log_dir = "./log/"                             # def ./dir for save log file, or create
csvFile= "" 
log_file="" 
pcap_file="" 

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
    

def info(start_time,num_of_request):   
    """
    This function print info time duration and total request
    """
    end_time = datetime.now()
    lgr.info('Duration: {}'.format(end_time - start_time)) 
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==True :
       lgr.info('Total request of reconnaissance: %d', fuzz_session.num_of_reco)
       lgr.info('Total request: %d', fuzz_session.num_of_request)     
    elif fuzz_session.fuzz_mode==True :
        lgr.info('Total request: %d', fuzz_session.num_of_request)     
 

def signal_handler(signal, frame): 
   """
   This function cleans temporary files and stop the fuzzer 
   upon Ctrl+c event

   """
   lgr.info('Stopping  Ctrl+c ')
   info(start_time,fuzz_session.num_of_request)       # info time and request
   fuzz_session.master1.close()
   sys.exit(0)


def Cleaning_up(): 
   """
   This function cleans temporary log files, 
   log_dir = "./log/" and fil*.pcap files
   """
   global log_dir     
   lgr.info('Cleaning up log files and pcap')
   os.system('sudo rm -rf ' + log_dir + '*.log.*')
   os.system('sudo rm -rf ' + log_dir + '*.log')
   os.system('sudo rm -rf ' + './fil*.pcap')   
   

def add_integer_bound(first, last,b):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.
        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''
        li=[]
        for i in range(-b, +b):
            case = first + i;li.append(case)     
            case = first - i;li.append(case)
            case = last + i;li.append(case)     
            case = last - i;li.append(case)
        #li.append(last); li.append(first);    
        return list([x for x in li if x>=0 and  x<=65535])

def fuzz_ad_list (first,last) :
    """
    address list append boundary value
    """
    li=[]
    li.append((first+1))
    li.append((first+2))
    li.append((first+3)) 
    li.append((first+4))
    li.append((first+5))
    li.append((first-1))
    li.append((first-3))
    li.append((first-2))
    li.append((first-4))
    li.append((first-5))
    li.append((last+1))
    li.append((last+2))
    li.append((last-1))
    li.append((last-2))
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

class fuzzer_None:
    """ Fuzzig none, original message send"""
    def __init__(self):
      pass       
    
    def fuzz_field_None(self,pdu):
        adu="";cur_payload=pdu                        
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

    
    def init_new_session(self,pdu,slave):
       """
        When a new pdu is detected, the fuzzer also starts
        a new session, i.e. 
        fuzz_request = int(a),define request for each FC
        num_of_request, total number of request, in fuzz_session.py  num_of_request=0 def

       """
       global num_of_request,fuzz_request
       F_session = Fuzz_session() 
       #import fuzz_session
       r=reconnect()
       fMbap=basetest.fuzzer_ADU() #ver 1.1. set
       fPayload=basetest.fuzzer_payload (); fPdu=basetest.fuzzer_pdu()
       lgr.info('');lgr.info('\t New request ------> %d',fuzz_session.num_of_request+1)      # + Num of request
       seed = time.time()                                                       #seed time  
                                                     #Class in master_fuzzer 
       fuzz_session.num_of_request += 1                                         # + Num of request all
       fuzz_session.count_num_of_fc -= 1                                        # + Num of request each FC             
       if fuzz_session.count_num_of_fc==0 :
          fuzz_session.count_num_of_fc=fuzz_session.num_of_fc
          #
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
          adu,pdu=fPayload.fuzz_payload(pdu) 
          return adu,pdu        
       elif F_session.fuzz == 'field_ADU':
          lgr.info('Fuzzing a field in MBAP') 
          adu=fMbap.fuzz_field_mbap(pdu,slave) 
          return adu,pdu         
       elif F_session.fuzz == 'field pdu':
       	  fuzz_session.fuzz_two_fields=False 
          lgr.info('Fuzzing a field  in PDU')
          adu,pdu=fPdu.fuzz_field_pdu(pdu) 
          return adu,pdu 
       elif F_session.fuzz == 'two fields in message':
          lgr.info('Fuzzing two or more fields in message')
          fuzz_session.fuzz_two_fields=True                  
          adu,pdu=fPdu.fuzz_field_pdu(pdu)               
          return adu,pdu
       elif F_session.fuzz == 'Not_fuzz':
          lgr.info('Valid message (not fuzzing)')
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
        self.fuzz_session.master1 = modbus_tcp_b.TcpMaster_b() 
        self.fuzz_session.master1.set_timeout(1.0)
        self.fuzz_session.master1.open()
        time.sleep(1.0)
    
    def tearDown(self):
        self.fuzz_session.master1.close()

    
    def con (self):
                global forever,FCmergedlist, ever               
                t=basetest.TestQueries();r=reconnect()  
                               
                while True:                                                                          
                    try:
                        """fuzzer function exec """                

                        if READ_COILS in FCmergedlist:
                            
                            """Check that read coil queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 01: READ_COILS .... ')                            
                            t.test_readcoil()   
                            lgr.info('\t Finally!  Fuzzer READ_COILS  DONE !!.' )
                            FCmergedlist.remove(READ_COILS)                            

                        elif READ_DISCRETE_INPUTS in FCmergedlist :       

                            """Check that ReadDiscreteInputs queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 02: READ_DISCRETE_INPUTS.... ') 
                            t.test_ReadDiscreteInputs()
                            lgr.info('\t Finally!  Fuzzer READ_DISCRETE_INPUTS!!.' )
                            FCmergedlist.remove(READ_DISCRETE_INPUTS)
                           
                        elif READ_HOLDING_REGISTERS in FCmergedlist : 
                           
                            """Check that  READ_HOLDING_REGISTERS queries are handled correctly"""
                            lgr.info('')
                            lgr.info(' \t Fuzzing  FC 03: READ_HOLDING_REGISTERS .... ')
                            t.test_readhr()
                            lgr.info(' \t Finally!  Fuzzer READ_HOLDING_REGISTERS DONE !!.' )
                            FCmergedlist.remove(READ_HOLDING_REGISTERS)
 
                        elif READ_INPUT_REGISTERS  in FCmergedlist :
                                                   
                            """Check that  queries READ_INPUT_REGISTERS are handled correctly"""
                            lgr.info('')
                            lgr.info(' \t Fuzzing  FC 04: READ_INPUT_REGISTERS... ') 
                            t.test_ReadAnalogInputs()
                            lgr.info('\t Finally!  Fuzzer READ_INPUT_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(READ_INPUT_REGISTERS)
                              
                        elif WRITE_SINGLE_COIL in FCmergedlist :
                           
                            """Check that write coil queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 05: WRITE_SINGLE_COIL .... ')
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
                            lgr.info('\t Fuzzing  FC 15: WRITE_MULTIPLE_COILS .... ')
                            t.test_WriteMultipleCoils()
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_COILS DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_COILS)                            
                        
                        elif WRITE_MULTIPLE_REGISTERS in FCmergedlist :

                            """Check that write WriteMultipleHr  queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 16: WRITE_MULTIPLE_REGISTERS .... ')
                            t.test_WriteMultipleHr()
                            lgr.info('\t Finally!  Fuzzer WRITE_MULTIPLE_REGISTERS  DONE !!.' )
                            FCmergedlist.remove(WRITE_MULTIPLE_REGISTERS)
                                                  
                        #Check that an error when the request is new function from pymodbus 1.2.0                   
                        elif Read_File_record in FCmergedlist :

                            """Check that Read_File_record queries are handled correctly"""
                            lgr.info('\t Fuzzing  FC 20: Read_File_record .... ')
                            t.test_ReadFileRecordRequestEncode()
                            lgr.info('\t Finally!  FuzzerRead_File_record  !!.' )
                            FCmergedlist.remove(Read_File_record)
                            
                        elif Write_File_record in FCmergedlist :      

                            """Check that Write_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 21: Write_File_record .... ')
                            t.test_WriteFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzzer Write_File_record   DONE !!.' )
                            FCmergedlist.remove(Write_File_record )                            
                              
                        elif Mask_Write_Register in FCmergedlist :      

                            """Check that Mask_Write_Register queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 22: Mask_Write_Register .... ')
                            t.test_MaskWriteRegisterRequestEncode()
                            lgr.info('\t Finally!  Mask_Write_Register DONE !!.' )
                            FCmergedlist.remove(Mask_Write_Register)                            
                              
                        elif Read_Write_Multiple_Registers in FCmergedlist :      

                            """Check that Read_Write_Multiple_Registers are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 23: Read_Write_Multiple_Registers .... ')
                            t.test_ReadWriteMultipleRegistersRequest()
                            lgr.info('\t Finally!  Read_Write_Multiple_Registers !!.' )
                            FCmergedlist.remove(Read_Write_Multiple_Registers)
                  
                        elif Read_FIFO_queue in FCmergedlist :  

                            """Check that ReadFifoQueueRequestEncode queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 24: Read_FIFO_queue  .... ')
                            t.test_ReadFifoQueueRequestEncode()
                            lgr.info('\t Finally!  Fuzzer Read_FIFO_queue  DONE !!.')
                            FCmergedlist.remove(Read_FIFO_queue)
                                                                   
                        
                        elif Read_device_Identification in FCmergedlist :  

                            """Check ReadDeviceInformationRequest queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 43: Read Device Identification interface  .... ')
                            t.test_Read_Device_Information()
                            lgr.info('\t Finally! Fuzz testing  Read Device Identification   DONE !!.')
                            FCmergedlist.remove(Read_device_Identification) 

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
                                           lgr.critical('Connection it lost after %d request..try reconnection !'%fuzz_session.stimeout);time.sleep(5.0)
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
                    
                    except  Exception as er:                                                             #default                         
                           lgr.error(er);lgr.error('Exit and try creating socket again') 
                           traceback.print_exc()                  
                           time.sleep(1.0)
                           #pass # in process normal no  # traceback.print_exc() 
                           break  # in process   with traceback.print_exc()       
                                                                                                                                                                      
                lgr.info("Finally! . Fuzzer all DONE !!.")
                fuzz_session.master1.close()                                                                                                                                                                      
   

def Read_CSvFile():
    """
    Read csv file for config fuzzer/calc fuzz address list
    """
    global start_address,last_address,mem_step,FCmergedlist,MIN_COILS,MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG 
    FCValues0 = []                                             
    FCValues1 = []
    IN_REG=[] 
    COILS=[]
    DIS_IN =[]
    HO_REG=[]
    p=basetest.dict_fuzz_object()   

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
            fuzz_session.MIN_COILS =min(COILS )
            fuzz_session.MAX_COILS =max(COILS )
            fuzz_session.MIN_IN_REG=min(IN_REG)
            fuzz_session.MAX_IN_REG=max(IN_REG)
            fuzz_session.MIN_DIS_IN=min(DIS_IN)
            fuzz_session.MAX_DIS_IN=max(DIS_IN)
            fuzz_session.MIN_HO_REG=min(HO_REG)
            fuzz_session.MAX_HO_REG=max(HO_REG)
                                   
            #calculate fuzz address for coils and register 
            fuzz_session.fuzz_addre_COILS=add_integer_bound(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS,5)+fuzz_session.Common_add_fuz 

            fuzz_session.fuzz_addre_DIS_IN=add_integer_bound(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN,5)+fuzz_session.Common_add_fuz 
            fuzz_session.fuzz_addre_IN_REG=add_integer_bound(fuzz_session.MIN_IN_REG,fuzz_session.MAX_DIS_IN,5)+fuzz_session.Common_add_fuz
            fuzz_session.fuzz_addre_HO_REG=add_integer_bound(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG,5)+fuzz_session.Common_add_fuz

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
            lgr.info('     > Configuration a probability of applying the fuzz categories')                  
            lgr.info('prob_list  : %s'%prob_list)                          
            lgr.info('')
            lgr.info('     > Configuration Read from CSV')
            lgr.info('FCs/FCsupport (mergedlist): %s'%FCmergedlist)            
            lgr.info('COILS_list   : %s' %COILS)
            lgr.info('DIS_IN_list  : %s' %DIS_IN)            
            lgr.info('HO_REG list  : %s' %HO_REG)            
            lgr.info('IN_REG_list  : %s' %IN_REG)           
            lgr.info('')
            lgr.info('     > Set Configuration') 
            lgr.info('start_address READ_COILS : %d' %fuzz_session.MIN_COILS )  
            lgr.info('last_address READ_COILS : %d' %fuzz_session.MAX_COILS )
            lgr.info('start_address READ_DISCRETE_INPUTS: %d' %fuzz_session.MIN_DIS_IN)
            lgr.info('last_address READ_DISCRETE_INPUTS: %d' %fuzz_session.MAX_DIS_IN)
            lgr.info('start_address READ_HOLDING_REGISTERS: %d' %fuzz_session.MIN_HO_REG)
            lgr.info('last_address READ_HOLDING_REGISTERS: %d' %fuzz_session.MAX_HO_REG)
            lgr.info('start_address READ_INPUT_REGISTERS: %d' %fuzz_session.MIN_IN_REG)
            lgr.info('last_address READ_INPUT_REGISTERS: %d' %fuzz_session.MAX_IN_REG)
            
            #log set configuration quantity_of_x_list, address in PDU fields 
            lgr.info('')
            lgr.info('Fuzzing address READ_COILS: %r' %fuzz_session.fuzz_addre_COILS)
            lgr.info('total of test/num address COILS: %d' %len(fuzz_session.fuzz_addre_COILS)) 
            lgr.info('Fuzzing address READ_DISCRETE_INPUTS: %r' %fuzz_session.fuzz_addre_DIS_IN)
            lgr.info('total of test/num address COILS: %d' %len(fuzz_session.fuzz_addre_DIS_IN))
            lgr.info('Fuzzing  address READ_INPUT_REGISTER: %r' %fuzz_session.fuzz_addre_IN_REG)
            lgr.info('total of test/num address COILS: %d' %len(fuzz_session.fuzz_addre_IN_REG))
            lgr.info('Fuzzing address READ_HOLDING_REGISTERS: %r' %fuzz_session.fuzz_addre_HO_REG)
            lgr.info('total of test/num address COILS: %d' %len(fuzz_session.fuzz_addre_HO_REG))
            lgr.info('')

            #log set configuration Smart values and operation fuzzing'
            lgr.info('     > Set Configuration Smart values and operation fuzzing')
            lgr.info('Set Configuration Smart values')
            lgr.info("\n".join("('{}':{})".format(k, v) for k, v in p.dict_smart_value().items()))
            lgr.info('')
            lgr.info('     > Set operation fuzzing') 
            lgr.info("\n".join("('{}:{})".format(k, v) for k, v in p.dict_operation().items()))                    
            lgr.info('')
            lgr.info('     > Set Configuration for function 20,21,22')
            lgr.info('start_address start_address_records : %d' %start_address_reco)
            lgr.info('last_address last_address_records : %d' %last_address_reco)

    except IOError:
            lgr.error('No such file or directory: search.csv')
            sys.exit(1)
                    
#------------------------------------------------------------
# The main fuzzer function
# set parametre host 
# start with a socket at 1-second timeout
#------------------------------------------------------------
def do_work( forever=True):
    global num_of_request,host
    
    while True:
        MAXIMUM_NUMBER_OF_ATTEMPTS=3
        lgr.info("Creating the socket")          
        fuzz_session.master1.__init__(host=host, port=502, timeout_in_sec=1.0)

        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
            try:           
                fuzz_session.master1.open_b()
                lgr.info('Socket connect worked!')                             
                start_fuzzer()       
                 
            #except EnvironmentError as exc:
            except socket.error:
                lgr.error('Socket connect failed! Loop up and try socket again')               
                time.sleep( 1.0)
                continue
        else :
            lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)            
            lgr.info("Fuzzer terminate !!.")
            fuzz_session.master1.close()
            sys.exit(1)

  
def start_fuzzer():
    """
    Initializing Fuzzer started, 
    int smart_value and fuzz_operation (p.int_smart_value,p.int_fuzz_operation() 
    """
    global running,fuzz_mode,search_mode,start_time,end_time,num_of_request,pcap_mode
    start_time = datetime.now()                             #start time for duration time      
    lgr.info('Initializing fuzz log reader');lgr.info('Fuzzer started')
    p=basetest.dict_fuzz_object()
    p.int_smart_value(); p.int_fuzz_operation()
   
    # phase I Search FC and address
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode==False:
            lgr.info('Running  in Search_mode True!')
            b_box=basetest.black_box()                       # object for scan  function support ans map address 
            b_box.con_SUT()                                  #run test black box                                  
            info(start_time,fuzz_session.num_of_request)     #info time and request 
            sys.exit(1)                                        
            
    elif  fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode== True :
            lgr.info('Running  in search mode True and pcap mode!')
            b_box=basetest.black_box_pcap()       # object for scan  function support ans map address            
            b_box.con_SUT_pcap()                             #read pcap file and add info in csv file          
            info(start_time,fuzz_session.num_of_request)
            sys.exit(1)   

    elif  fuzz_session.search_mode==False and fuzz_session.fuzz_mode==True and fuzz_session.pcap_mode== False:      
            """fuzzer operation querie, search_mode False from command line param"""

            lgr.info('Running in search_mode False and fuzz_mode True ! ');
            Read_CSvFile()                                     #read file csv and append list for configuration          
            s=SetupAndTeardown()                               #object for fuzzer            
            s.con()                        
            info(start_time,fuzz_session.num_of_request)       #info time and request             
            sys.exit(1)                                       
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==False:
            lgr.info('Running in search mode True and fuzzing mode True ')
            
            #run test black box            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False          
            b_box=basetest.black_box()                         # object for scan  function support ans map address, 
            b_box.con_SUT()                                    #run test black box 
            
            #run fuzzer mode and read csvFile
            fuzz_session.search_mode=False
            fuzz_session.fuzz_mode=True            
            Read_CSvFile()                                     #read file csv and append list for configuration
            s=SetupAndTeardown()                               #object for fuzzer            
            s.con()                                            #fuzzer querie 
            info(start_time,fuzz_session.num_of_request)       #info time and request 
            sys.exit(1) 
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==True :
            lgr.info('Running in search mode and fuzzing mode on pcap file')
            
            #run read from pcap file            
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False                       
            lgr.info('Running in search mode True and pcap_mode!')
            b_box=black_box()                                 #object for scan  function support ans map address            
            b_box.con_SUT_pcap()                              #read pcap file and add info in csv file 
                                      
            #run fuzzer mode and read csvFile
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
   lgr.info('SUT Unit IP address: ' + host )                          #ip address SUT  
   lgr.info('log_file: ' + filename1 + filename2 )
   lgr.info('csvFile: ' + csvFile)                          #file name auto for logger
   lgr.info('pcap_file: ' + pcap_file) 
   lgr.info('fuzzing request for each FC: %d',fuzz_request)
                                   
   if (pcap_file != "" and csvFile != ""):      
      start_fuzzer() 

   elif(host is None  or csvFile == ""):
      print_usage();sys.exit(0)
      
   elif (fuzz_session.search_mode==False and fuzz_session.fuzz_mode==False):
      print_usage() 
      sys.exit(0)        
   do_work(True)   #start with a socket at 1-second timeout,set parametre host and start_fuzzer 
   
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    Cleaning_up()                                        #Cleaning up  log files 
    fuzz_session.master1 = modbus_tcp_b.TcpMaster_b()    #set param master1         object  ,    
    log_info(lgr,logger) 
    main()

    
