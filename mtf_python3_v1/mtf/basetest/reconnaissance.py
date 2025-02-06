#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import traceback
import math
import sys
import csv
import itertools
import  struct 
import time
import logging
import logging.handlers as handlers

import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b
import fuzz_session 
from itertools import zip_longest
from itertools import count 
from itertools import chain
from scapy.all import *
import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.contrib.modbus import *             
from product.message import ReadDeviceInformationRequest,ReadDeviceInformationResponse #library from pymodbus v2.1.0  
from utils_b import flush_socket_b,get_log_buffer_b,threadsafe_fun 
from defines import *  #define  function, exeption e.a
from add_method  import ByteToHex
from raise_except import (CsvError,TestfieldError,ModbusError) #exception for raise_except   
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('')

#-----------------------------------------------------------------------------------------------------------#
# This Class fuzzes // verify function code and mapping address
# list_csv=[],  list of list results of search
#-----------------------------------------------------------------------------------------------------------#
class black_box(object):
   

    def __init__(self,csvFile="search.csv" ,scv_table='dump_memory.csv',quan_step=1,s_address=0,l_address=65535,step=1024): 
        """
        
        @param master1         object ,define slave=1 ,fuzz_session.master1 
        @param csvFile:        search.csv, file to save FC and address results of search 
        
        @type        int
        @param s_address       define for search mapping block
        @param l_address
        @param step
        @param quan_step:      step for search map

        @param quantity        set step for read block memory with memory dump attack
        @param scv_table
        @param step_mem_dump

        @param                 Read csv file and memory dump attacks
        FCValues0                                              
        FCValues1 
        IN_REG 
        COILS
        DIS_IN 
        HO_REG

        @param                  with master fuzz testing
        start_address=0
        last_address=40000
        size_of_bank=9999
        offset_fuzzer=0         up - down bank memory 
        name_of_block=None
        value_range=64          quantity_of_x how value read 
        mem_step=1024           how match move to memory -step

              
        """
        self.csvFile=csvFile
        self.csvHeading= ["FC_1","FC_2","IN_REG","COILS","DIS_IN","HO_REG"]
        self.list_csv=[]
        self.csv_Heading_memory=["address_read","Value"]
        self.rang_memory=[]                                                           #add addres eg (0,100) as tumple/etch time
        self.list_of_results=[]                                                       #list of list results of search/tuples
        self.s_address=s_address
        self.l_address=l_address
        self.step=step
        self.quan_step=quan_step

        #set step for read block memory with memory dump attack ,from def...py
        self.scv_table=scv_table
        self.quantity=100
        self.step_mem_dump=100

        self.FCValues0 = []                                             
        self.FCValues1 = []
        self.IN_REG=[] 
        self.COILS=[]
        self.DIS_IN =[]
        self.HO_REG=[]
        
    def reconnection_do_work(self,ever=True) :
        global host               
        
        MAXIMUM_NUMBER_OF_ATTEMPTS=3                        
        lgr.info("Creating the socket host %s"%host)
        fuzz_session.master1.__init__(host=host, port=502, timeout_in_sec=1.0)

        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
            try:           
                fuzz_session.master1.open_b()
                lgr.info(''); lgr.info('\t Socket connect worked!')
                break;                                                           
            # except EnvironmentError as exc:
            except socket.error:
                lgr.error('Socket connect failed! Loop up and try socket again') 
                time.sleep(1.0);continue               
        else :                
                lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)                            
                lgr.info("Fuzzer terminate !!.")
                info(start_time,num_of_request)       # info time and request
                fuzz_session.master1.close();sys.exit(1)    
    
    def _reset_state(self):
        """
        Restart the object's 

        :return: None
        """
        self.s_address=0
        self.l_address=65535
        self.step=1024

    # this method write results of search black box to file csv    
    def WriteCSVFile (self,csvFile,list_csv): 
       
        ofile  = open(self.csvFile, "w")        
        writer = csv.writer(ofile, delimiter='\t')
        writer.writerow(self.csvHeading)                             
        for values in zip_longest (*list_csv):  
            writer.writerow(values)      
        ofile.close()    

    def WriteCSVblock (self,scv_table):
        """
    	this method write results of  memory dump attack to file csv  each table memory block 
        self.scv_table='dump_memory.csv' 
        """
        
        ofile  = open(scv_table, "w")        
        writer = csv.writer(ofile,delimiter='\t')
        for values in zip_longest (self.rang_memory,self.list_of_results):
            writer.writerow(values)                                          #making header here             
        ofile.close()  


    def setUp(self): #tuples
        ''' Initializes the test environment, this method copy for Pymodbus,test_factory.py '''
        
        self.request = (
               
                (0x01, b'\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, b'\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, b'\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, b'\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, b'\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, b'\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, b'\x07'),                                       # read exception status
                (0x08, b'\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, b'\x0b'),                                       # get comm event counters
                (0x0c, b'\x0c'),                                       # get comm event log
                (0x0f, b'\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, b'\x10\x00\x01\x00\x02\x04\x01\x02\x01\x02'),   # write multiple registers 
                (0x11, b'\x11'),                                       # report slave id
                (0x14, b'\x14\x0e\x06\x00\x04\x00\x01\x00\x02' 
                       b'\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, b'\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       b'\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, b'\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, b'\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, b'\x18\x00\x01'),                               # read fifo queue
                (0x2b, b'\x2b\x0e\x01\x00'),                           # read device identification,crash tmw v3.26                   
        )

        self.response = (
                (0x01, b'\x01\x01\x01'),                               # read coils
                (0x02, b'\x02\x01\x01'),                               # read discrete inputs
                (0x03, b'\x03\x02\x01\x01'),                           # read holding registers
                (0x04, b'\x04\x02\x01\x01'),                           # read input registers
                (0x05, b'\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, b'\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, b'\x07\x00'),                                   # read exception status
                (0x08, b'\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, b'\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, b'\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, b'\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, b'\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, b'\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, b'\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' \
                       b'\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, b'\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       b'\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, b'\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, b'\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, b'\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, b'\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

        self.bad = (
                (0x80, b'\x80\x00\x00\x00'),                           # Unknown Function
                (0x81, b'\x81\x00\x00\x00'),                           # error message
                (0x90, b'\x90\x00\x00\x00'),
                (0x91, b'\x91\x00\x00\x00'),
                (0x92, b'\x92\x00\x00\x00'),
                (0x93, b'\x93\x00\x00\x00'),
                (0x94, b'\x94\x00\x00\x00'),
                (0x95, b'\x95\x00\x00\x00'),
                (0x96, b'\x96\x00\x00\x00'),
                (0x97, b'\x97\x00\x00\x00'),
                (0x98, b'\x98\x00\x00\x00'),
                (0x99, b'\x99\x00\x00\x00'),     
        )
        
        self.exception = (
                (0x81, b'\x81\x01\xd0\x50'),                           # illegal function exception
                (0x82, b'\x82\x02\x90\xa1'),                           # illegal data address exception
                (0x83, b'\x83\x03\x50\xf1'),                           # illegal data value exception
                (0x84, b'\x84\x04\x13\x03'),                           # skave device failure exception
                (0x85, b'\x85\x05\xd3\x53'),                           # acknowledge exception
                (0x86, b'\x86\x06\x93\xa2'),                           # slave device busy exception
                (0x87, b'\x87\x08\x53\xf2'),                           # memory parity exception
                (0x88, b'\x88\x0a\x16\x06'),                           # gateway path unavailable exception
                (0x89, b'\x89\x0b\xd6\x56'),                           # gateway target failed exception
        )
        
        self.diagnostics = (
        
        (00, b'\x08\x00\x00\x00\x00'),
        (0o1, b'\x08\x00\x01\x00\x00'),
        (0o2, b'\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (0o3, b'\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (0o4, b'\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (0o5, b'\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (0o6, b'\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (0o7, b'\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, b'\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, b'\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, b'\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, b'\x08\x00\x0f\x00\x00'),                               # ReturnSlaveNoReponseCountResponse
        (14, b'\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, b'\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, b'\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, b'\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, b'\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, b'\x08\x00\x15' + b'\x00\x00' * 55),                    #GetClearModbusPlusResponse
        (20, b'\x08\x00\x01\x00\xff'),                               #restartCommunaications
       )


    def remove_duplicates(self,l):
        return list(set(l))

    #scan for address coil support, return list support    
    def scan_coil(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=fuzz_session.master1.execute_f(slave, READ_COILS , address_fuz, self.quan_step) 
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_coil)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_INPUT_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=fuzz_session.master1.execute_f(slave, READ_INPUT_REGISTERS , address_fuz, self.quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_DISCRETE_INPUTS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=fuzz_session.master1.execute_f(slave, READ_DISCRETE_INPUTS , address_fuz, self.quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_dist_input)
        return list
    
    #scan for_address_input_reg support, return list support    
    def scan_READ_HOLDING_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=fuzz_session.master1.execute_f(slave,READ_HOLDING_REGISTERS , address_fuz, self.quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_hold_reg)
        return  list   

    
    def chk_list_Up(self,list):
        """check list of support address for number of elements min 3 elements"""
	
        self._reset_state()
        lgr.info('check list up');lgr.info('')         
                                                     
        if list==supported_address_coil :
            while self.step!=1 :
                self.step=self.step//2
                if  len(list) == 0:                           #empty list                                  
                    self.scan_coil(self.s_address,self.l_address,self.step,list)                    
                                                                                                            
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)                  
                    if len(list) == 0 :
                        max_el=0
                    #set s_address is max item of list
                    self.s_address=max_el
                    self.l_address=self.s_address+(2*self.step)
                    if self.l_address>65535 :
                        self.l_address=65535              
                    #call
                    self.scan_coil(self.s_address,self.l_address,self.step,list)                                                                           
                                                                   
        elif list==supported_address_input_reg :
            
            while self.step!=1 :
                self.step=self.step//2
                if  len(list) == 0:                           #empty list                                   
                    self.scan_READ_INPUT_REGISTERS(self.s_address,self.l_address,self.step,list)                            
                
                else  :                                       #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)          
                    if len(list) == 0 :
                    	max_el=0#min_el=min(list)
                    #set s_address is max item of list
                    self.s_address=max_el
                    self.l_address=self.s_address+(2*self.step)
                    if self.l_address>65535 :
                        self.l_address=65535                
                    #call
                    self.scan_READ_INPUT_REGISTERS(self.s_address,self.l_address,self.step,list)                                            
                       
        elif list==supported_address_dist_input :
               
            while self.step!=1 :
                self.step=self.step//2
                if  len(list) == 0:                           #empty list                
                    self.scan_READ_DISCRETE_INPUTS(self.s_address,self.l_address,self.step,list)                           
                
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    if len(list) == 0 :
                        max_el=0#min_el=min(list) 
                    self.s_address=max_el
                    self.l_address=self.s_address+(2*self.step)
                    if self.l_address>65535 :
                        self.l_address=65535                
                    #call
                    self.scan_READ_DISCRETE_INPUTS(self.s_address,self.l_address,self.step,list)                        
                     
        elif list==supported_address_hold_reg :   
            
            while self.step!=1 :
                self.step=self.step//2
                if  len(list) == 0:                                                              
                    self.scan_READ_HOLDING_REGISTERS(self.s_address,self.l_address,self.step,list)                                                                 
                else  :                                       #first address 0/not empty list                
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    self.s_address=max_el
                    self.l_address=self.s_address+(2*self.step)
                    if self.l_address>65535 :
                        self.l_address=65535                
                                        
                    self.scan_READ_HOLDING_REGISTERS(self.s_address,self.l_address,self.step,list)                                                                             
        else :
            pass                
        return   

    def chk_list_down(self,list):
        """check list of support address for number of elements min 3 elements"""
        lgr.info('Check list down');lgr.info('')

        if len(list) == 0:
            pass        
        elif min(list)!=0 :
            min_el=min(list)
            self.step=min_el//2
            #init value
            self.s_address=0
            self.l_address=min_el                                                           
            while self.step!=1 :
                self.step=self.step//2
                self.s_address=min(list)-(2*self.step)
                self.l_address=min(list)
                
                if list==supported_address_coil:
                    self.scan_coil(self.s_address,self.l_address,self.step,list)
                                                    
                elif list==supported_address_dist_input :
                    self.scan_READ_DISCRETE_INPUTS(self.s_address,self.l_address,self.step,list)                   

                elif list==supported_address_hold_reg :
                    self.scan_READ_HOLDING_REGISTERS(self.s_address,self.l_address,self.step,list)
                    
                elif list==supported_address_input_reg : 
                    self.scan_READ_INPUT_REGISTERS(self.s_address,self.l_address,self.step,list)                                                       
        else :
            pass        
        
        return      
   
    def ReqsupportFunc(self):
        """ Looking for supported function codes with wall pdu request (self.request)"""   

        supportedFunc = []        
        lgr.info('\n \t \t  Looking for supported function codes..with wall pdu request')
        socket_flag=False;index = 0
        
        while index<len(self.request):
            response_pdu=fuzz_session.master1.execute_master(slave,self.request[index][1]) 
            lgr.info('The response pdu: -----> %r '% ByteToHex(response_pdu))                   
            # We are using the raw data format, because not all function
            # codes are supported out by this library.
            if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')                    
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')
                # If return function code is > 128 --> error code 
                if returnCode > 127 and exceptionCode == 0x01:       
                  lgr.warn("Function Code: "+str(self.request[index][0])+" not supported." )                 
                else:
                  supportedFunc.append(self.request[index][0])
                  lgr.info("Function Code: "+str(self.request[index][0])+" is supported." )
                index +=1 ;socket_flag=False   
            else: #case socket timeout or not response 
                #send message again/repait 
                if socket_flag==False:
                    socket_flag=True                   
                    lgr.warn("Function Code:"+str(self.request[index][0])+" probably supported, repeat message .." )
                    index = index 
                else: socket_flag=False;index +=1
                #supportedFunc.append(func)  #not add probably supported Function Code        
        lgr.info('\n \t  \t  The Function code supported / pdu search') #function list support
        self.print_results_blackbox(FC =supportedFunc)
        return supportedFunc

    def getSupportedFunctionCodes(self):
        """
        Verifies which function codes are supported by a Modbus Server-copy for modlib.py
        Returns a list with accepted function codes
        """
        supportedFuncCodes = []
        lgr.info("\n \t \t Looking for supported function codes (1-127) with ModbusPDU_Generic")
        for fct in range(0,128,1):                     
            pdu=struct.pack(">B",fct) + (('\x00\x00').encode()+('\x00\x01').encode())
            response_pdu=fuzz_session.master1.execute_master(slave,pdu)
            lgr.info('The response pdu: ----->%r '% ByteToHex(response_pdu))        
            # We are using the raw data format, because not all function
            # codes are supported out by this library.
            if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')
                
                if returnCode > 127 and (exceptionCode == 1 or exceptionCode == 3): 
                  # If return function code is > 128 --> error code
                  lgr.warn("Function Code: "+str(fct)+" not supported." )                  
                else:  
                    if fct==returnCode:
                      supportedFuncCodes.append(fct)
                      lgr.info("Function Code: "+str(fct)+" is supported." )
                    else:lgr.warn("Function Code: "+str(fct)+" probably supported." )  
            else:
              lgr.warn("Function Code:"+str(fct)+" probably supported." )
              #not add probably supported Function Code, add supportedFuncCodes.append(fct)    
                                                  
        #print (log) function list supported        
        lgr.info('\n-----------    The Function code supported / search FC 1-127  --------------')              
        self.print_results_blackbox(FC =supportedFuncCodes)
        return supportedFuncCodes

    def getSupportedDiagnostics(self):                     # Not use  
        """"
        if connection == None:
        return "Connection needs to be established first.
        Total of 65535, function code 8, sub-function code is 2 bytes long
        supportedDiagnostics = []
        """
        lgr.info("Looking for supported diagnostics codes..")
        for i in range(0,65535):       #
          pdu="\x08"+struct.pack(">H",i)+"\x00\x00"
          response=fuzz_session.master1.execute_master(slave,pdu) 

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
          
    def get_Supported(self,address_fuz,response_pdu,mylist,not_resp_list): 
        """
        Verifies which address are supported 
        Returns a list with accepted address
        """
        returnCode="";exceptionCode =""
        lgr.info('The response pdu:%r'%ByteToHex(response_pdu))
        if response_pdu:                
                returnCode=int.from_bytes(response_pdu[0:1], byteorder='big')                 
                exceptionCode=int.from_bytes(response_pdu[1:2], byteorder='big')
                lgr.info('The returnCode is: %d ' % returnCode) 
                if returnCode > 127 and (exceptionCode == 2):  
                  # If return function code is > 128 --> error code
                  lgr.info("Fuzz_address "+str(address_fuz)+" not supported." )
                  lgr.info('')
                else:
                    if address_fuz not in mylist :                                            
                        mylist.append(address_fuz)
                        lgr.info("Fuzz address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
                    else :
                        lgr.info("Fuzz address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
        else : #case socket timeout or not response 
              lgr.warn("Fuzz_address  "+str(address_fuz)+" probably supported." )
              #add in list of support address
              #mylist.append(address_fuz)                   
              #add in list for not support address list for use possible later
              not_resp_list.append(address_fuz)  
              
        return  mylist.sort(),not_resp_list.sort()   

    
    def printmap_address(self,*args):
        """print supported address ..for data bank  - -NOT USE  """
        for arg in args :       
            print('"\n"----Check for' +'%r' %arg + 'address  supported --------------', file=sys.stderr)          
            print((" ".join(map(str, list))))
        return   
  
      
    def getaddress(self):
      """Check for supported address ..for data bank"""

      response_pdu=""
      
      lgr.info('\n \t \t  Looking for READ_COILS, supported address ..')      
      #check elements of the list support address/upper 
      self.chk_list_Up(supported_address_coil)
      #if min item of list not 0
      self.chk_list_down(supported_address_coil)
      
      #Check that response for read analog inputs (READ_INPUT_REGISTERS) function
      lgr.info('\n \t \t  Looking for READ_INPUT_REGISTERS supported address ..')         
      self.chk_list_Up(supported_address_input_reg)      
      #if min item of list not 0
      self.chk_list_down(supported_address_input_reg)

      #Check that response for read digital inputs function 
      lgr.info('\n \t \t  Looking for READ_DISCRETE_INPUTS  supported address ....')      
      self.chk_list_Up(supported_address_dist_input)     
      #if min item of list not 0
      self.chk_list_down(supported_address_dist_input)
      
      #Check that response for READ_HOLDING_REGISTERS function
      lgr.info('\n \t \t  Looking for READ_HOLDING_REGISTERS  supported address ..')    
      self.chk_list_Up(supported_address_hold_reg)
      #if min item of list not 0
      self.chk_list_down(supported_address_hold_reg) 
     
      #print  elements of the list support address
      self.print_results_blackbox(COILS =supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
      self.print_results_blackbox(NOT_RESP_COILS =not_response_address_coil,NOT_RESP_INPUT_REGISTERS=not_response_address_input_reg,NOT_RESP_DISCRETE_INPUTS=not_response_address_dist_input,NOT_RESP_HOLDING_REGISTERS=not_response_address_hold_reg)
      
      return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg 
    

    def Read_Device_Information(self):
        '''  
        basic message encoding                                        
        params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] }  
        handle  = ReadDeviceInformationRequest(**params)
        Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
    
        object Id Object Name / Description   Type   M/O    category  
     
          0x00  VendorName                   ASCII String  Mandatory  Basic 
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
          ----------------------------------------------------------------------- 
          
        Read Device ID code /read_code
            DeviceInformation_Basic:  0x01 , 
            DeviceInformation_Regular= 0x02 ,
            DeviceInformation_Extended= 0x03 ,
            DeviceInformation_Specific= 0x04 , 
        If the Object Id does not match any known object, the server responds as if object 0 were 
        pointed out (restart at the beginning) 
        '''      
        
        mei_object=[] 
        lgr.info('\n  \t \t  Looking for FC 43: READ Device Information (Error) SubFC: 14')
        # Read Device ID code
        for read_code in range(1,5,1) :                                    
            for object_id in range(0,127,1) :
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=fuzz_session.master1.execute_master(slave,result)                
                if response:                
                    returnCode=int.from_bytes(response[0:1], byteorder='big')                                      
                    exceptionCode=int.from_bytes(response[1:2], byteorder='big')                      
                    if returnCode > 127 and (exceptionCode == 2 or exceptionCode == 1 or exceptionCode == 3):
                        # If return function code is > 128 --> error code
                        lgr.info('The response: ---> %r exceptionCode: %r  ' % (ByteToHex(response),exceptionCode))
                        continue
                         
                    else :
                        #parse_response FC=43                  
                        message = response[1:len(response)] ;lgr.info('response message: ---> %r ' % ByteToHex(response))  
                        if len(message)<6 :
                            lgr.info('response message: --->  %r' % ByteToHex(message))
                            continue
                         
                        #read device information MESSAGE response  decode     
                        handle  = ReadDeviceInformationResponse()    # send to decode
                        handle.decode(message)
                        lgr.info('Read Device ID code,read_code : 0x%02X '% handle.read_code)  
                        lgr.info('Read Device ID code,object_id : 0x%02X '% object_id)           
                        lgr.info('Read Device ID code,conformity : 0x%02X' % handle.conformity )   
                           
                        #if  Object is in list ...
                        if handle.information not in  mei_object :                
                              mei_object.append(dict(handle.information))
                else :
                    lgr.info('The response: ---> %r ' % ByteToHex(response))
                                                  
        lgr.info('\n  \t \t Test device identification summary creation .....' )        
        lgr.info("\n".join(map(str, mei_object)))

    
    def print_results_blackbox(self,**kwargs): 
        """print supported address ..for data bank"""

        lgr.info('')
        for name, value in kwargs.items():
            lgr.info( '{0} = {1}'.format(name, value))
        #lgr.info('')
        return                

   
    def request_check(self):
        """ Looking for send  some pdu request bad,response,exception and diagnostics """     

        check_response1 = []
        check_response2 = []
        check_response3 = []
        check_response4 = []
        
        lgr.info('\n \t \t \t ......... send  wall  response..'  )
        for func, msg in self.response:
            response_pdu=fuzz_session.master1.execute_master(slave,msg )                  
            check_response1.append(ByteToHex(response_pdu))
            lgr.info('The response pdu: -----> %r ' % ByteToHex(response_pdu))                  
        
        lgr.info('\n \t \t \t ------  send  request bad..'  )
        for func, msg in self.bad:
            #response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            response_pdu=fuzz_session.master1.execute_master(slave,msg )
            check_response2.append(ByteToHex(response_pdu))
            lgr.info('response pdu: -----> %r ' % ByteToHex(response_pdu))   
        
        lgr.info('\n  \t \t \t .......... send  exception....')
        for func, msg in self.exception:
            #response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            response_pdu=fuzz_session.master1.execute_master(slave,msg )
            check_response3.append(ByteToHex(response_pdu))
            lgr.info('response pdu: -----> %r ' % ByteToHex(response_pdu))
        
        lgr.info('\n \t \t \t ........ send  diagnostics..')    
        for func, msg in self.diagnostics:
            #response_pdu=master1.execute_master(slave,bytearray(msg, 'utf-8'))
            response_pdu=fuzz_session.master1.execute_master(slave,msg )
            check_response4.append(ByteToHex(response_pdu))
            lgr.info('response pdu: -----> %r ' % ByteToHex(response_pdu))         
        
        lgr.info ('\n \t \t \t  Response of request ')
        self.print_results_blackbox(response =check_response1,bad=check_response2,exception=check_response3,diagnostics=check_response4)
        return check_response1,check_response2,check_response3,check_response4


    def con_SUT (self):

        """Check black_box and save csv file
            search.csv /file format/
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
            
        try:
                                                  
            """ Verifies which function codes are supported returns a list with accepted function codes/fuzz_mode=False """
            lgr.info('\n \t \t Verifies which function codes are supported  .....') 
            l1=self.getSupportedFunctionCodes()   #scan  function support
            
            #Add to clobal list the return list/list of list
            self.list_csv.append(l1)
                         
            """Function send request wall pdu request and from response create Supported Function Codes  list""" 
            lgr.info('\n \t \t  Create Supported Function Codes for send request wall pdu  .... .....') 
            self.setUp()
            l2=self.ReqsupportFunc()
            self.list_csv.append(l2)
            
            """ mapping address table      """
            l3,l4,l5,l6=self.getaddress()

            """case empty list / the SUT not response in address/return empty address list"""
            if len(l3) == 0:
                l3=[0,65535]
            if len(l4)==0  : 
                l4=[0,65535]
            if len(l5) == 0:
                l5=[0,65535]
            if len(l6) == 0:
                l6=[0,65535]       

            self.list_csv.append(l3)
            self.list_csv.append(l4)
            self.list_csv.append(l5)
            self.list_csv.append(l6)
           
            """ send request wall response/bad/exception """
            lgr.info('Send request wall response/bad/exception ....')
            self.setUp() 
            self.request_check()
          
            """ search Device_Information """                
            self.Read_Device_Information()

            """ Write to csv search results of blackbox """ 
            self.WriteCSVFile(self.csvFile,self.list_csv)
            
            """ memory read dump attack"""
            self.memory_dump()           
                                                                           
        except ModbusError as ex: 
           
           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
           pass     
                         
      
        except socket.timeout:
            lgr.error('Socket timeout, loop and try recv() again')
            time.sleep( 1.0)
            pass    
        
        except socket.error as socketerror:
            lgr.error("Socket Error: %s ", (socketerror))
            time.sleep( 1.0)
            self.reconnection_do_work(True)                                                      
        
        #default
        except  Exception as er:                                                                  
                #except:                                                                                      
                lgr.error(er);lgr.error('Exit and try creating socket again')
                time.sleep( 1.0)    
            
        finally:
                fuzz_session.master1.close()
                lgr.info('Total request of reconnaissance: %d', fuzz_session.num_of_reco)                    
                lgr.info("Finally! search all DONE !!.")                    
                
    
    def memory_dump(self):
        
        """ 
        Read csv file and memory dump attacks

        Address 0x    --> address and offset (eg ox for COILS) ....        
        Value READ_COILS  --> Value from address    
    
        Address 0x   Value READ_COILS   
        (1, 100)    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1....)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ....)
        ...................
        Address 3x   Value READ_INPUT_REGISTERS "   
        (1, 100)    (3333, 1, 2, 3, 0, 5, 0, 0, 0,  0, 0, 0, 0, 0, ... 0, 0, 0, 0, ..)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0,...)

        Restart the object's reader(open('search.csv'
        FCValues0 = []                                             
        FCValues1 = []
        IN_REG=[] 
        COILS=[]
        DIS_IN =[]
        HO_REG=[]

        """

        try :
                values = csv.reader(open('search.csv', 'r'), delimiter='\t')
                #read 0 colume
                for row in values:
                      self.FCValues0.append(row[0])
                      self.FCValues1.append(row[1])
                      self.IN_REG.append(row[2])
                      self.COILS.append(row[3])
                      self.DIS_IN.append(row[4])
                      self.HO_REG.append(row[5])    
                # pop header
                self.FCValues0.pop(0)    
                self.FCValues1.pop(0)    
                self.IN_REG.pop(0)   
                self.COILS.pop(0)    
                self.DIS_IN.pop(0)   
                self.HO_REG.pop(0)
                
                self.IN_REG = [_f for _f in self.IN_REG if _f]
                self.COILS = [_f for _f in self.COILS if _f]
                self.DIS_IN= [_f for _f in self.DIS_IN if _f]
                self.HO_REG = [_f for _f in self.HO_REG if _f]
                                                           
                #convert all strings in a list to ints
                self.IN_REG = [int(i) for i in self.IN_REG]
                self.COILS = [int(i) for i in self.COILS]
                self.DIS_IN = [int(i) for i in self.DIS_IN]
                self.HO_REG = [int(i) for i in self.HO_REG]  
                
                #for all list min/max address                           
                MIN_COILS =min(self.COILS )
                MAX_COILS =max(self.COILS )
                MIN_IN_REG=min(self.IN_REG)
                MAX_IN_REG=max(self.IN_REG)
                MIN_DIS_IN=min(self.DIS_IN)
                MAX_DIS_IN=max(self.DIS_IN)
                MIN_HO_REG=min(self.HO_REG)
                MAX_HO_REG=max(self.HO_REG)
                                                                           
                lgr.info('Memory dump READ REGISTERS .... ....')                 
                lgr.info('')                      
                lgr.info('Set Configuration for memory dump attacks')
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
                
                lgr.info('')
                lgr.info('Memory dump READ_COILS  ....(%d,%d) .offset:0X' % (MIN_COILS,MAX_COILS))               
                self.rang_memory.append('Address 0x \t Value READ_COILS')
                self.list_of_results.append('',) 
                
                for address_read in range (MIN_COILS ,MAX_COILS,self.step_mem_dump):                    
                        
                        if (address_read+self.quantity)>MAX_COILS :
                            self.quantity=(MAX_COILS-address_read)
                        lgr.info('')
                        lgr.info('First address_read: %s (%s) last_address: %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+self.quantity),hex(address_read+self.quantity)))
                        #write head for csv file
                        self.rang_memory.append((address_read+1,address_read+self.quantity))
                        result=fuzz_session.master1.execute_read_memory(slave, READ_COILS , address_read , self.quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))
                        #add results for list tuples
                        self.list_of_results.append(result,)                       

                """ Test  response for read digital inputs function (READ_DISCRETE_INPUTS )               
                        This function code is used to read from 1 to 2000 contiguous status of discrete inputs in a
                        remote device"""
                    
                lgr.info('')
                lgr.info('Memory dump READ_DISCRETE_INPUTS ..(%d,%d).offset:1X'%(MIN_DIS_IN,MAX_DIS_IN))
                #offset_dis_input=10000
                self.rang_memory.append('Address 1x \t Value READ_DISCRETE_INPUTS ')
                self.list_of_results.append('',) 
                for address_read in range (MIN_DIS_IN,MAX_DIS_IN,self.step_mem_dump):                    
                        self.quantity=self.step_mem_dump
                        if (address_read+self.quantity)>MAX_DIS_IN :
                            self.quantity=(MAX_DIS_IN-address_read)
                        lgr.info('')
                        lgr.info('First address_read: %s (%s) last_address: %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+self.quantity),hex(address_read+self.quantity)))
                        self.rang_memory.append((address_read+1,address_read+self.quantity))
                        result=fuzz_session.master1.execute_read_memory(slave, READ_DISCRETE_INPUTS, address_read , self.quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))                                                                  
                        self.list_of_results.append(result,)
                                     
                """ Test  response for read READ_INPUT_REGISTERS (READ_INPUT_REGISTERS ), offset_reg_in= 30000               
                    This function code is used to read from 1 to 125 contiguous input registers in a remote device"""                              
                lgr.info('')
                lgr.info('Memory dump READ_INPUT_REGISTERS ..(%d,%d)..offset: 3X' %(MIN_IN_REG,MAX_IN_REG))
                self.rang_memory.append('Address 3x \t Value READ_INPUT_REGISTERS ')
                self.list_of_results.append('',) 
                for address_read in range (MIN_IN_REG,MAX_IN_REG,self.step_mem_dump):                    
                        self.quantity=self.step_mem_dump
                        if (address_read+self.quantity)>MAX_IN_REG :
                            self.quantity=(MAX_IN_REG-address_read)
                        lgr.info('')
                        lgr.info('First address_read: %s (%s) last_address: %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+self.quantity),hex(address_read+self.quantity)))
                        self.rang_memory.append((address_read+1,address_read+self.quantity))
                        result=fuzz_session.master1.execute_read_memory(slave, READ_INPUT_REGISTERS , address_read , self.quantity)    #tuple                  
                        lgr.info('Answer >> result  %s '  % (result,))
                        self.list_of_results.append(result,)                                          

                """ Test  response for read HOLDING_REGISTERS  (HOLDING_REGISTERS ),Address 40001,offset_reg= 40000               
                    This function code is used to read from 1 to 125 contiguous holding registers in a remote device"""
                    
                lgr.info('')
                lgr.info('Memory dump HOLDING_REGISTERS  ..(%d,%d)..offset:4X' % (MIN_HO_REG,MAX_HO_REG))
                self.rang_memory.append('Address 4x \t Value HOLDING_REGISTERS')
                self.list_of_results.append('',)
                
                for address_read in range (MIN_HO_REG,MAX_HO_REG ,self.step_mem_dump):                    
                        self.quantity=self.step_mem_dump
                        if (address_read+self.quantity)>MAX_HO_REG :
                            self.quantity=(MAX_HO_REG-address_read)
                        lgr.info('')
                        lgr.info('First address_read: %s (%s) last_address: %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+self.quantity),hex(address_read+self.quantity)))
                        self.rang_memory.append((address_read+1,address_read+self.quantity))                        
                        result=fuzz_session.master1.execute_read_memory(slave, READ_HOLDING_REGISTERS , address_read , self.quantity)        #tuple                
                        lgr.info('Answer >> result  %s '  % (result,))
                        self.list_of_results.append(result,)     
                
                #Call function to write csv file
                self.WriteCSVblock(self.scv_table)                               
        
        except  Exception as er: 
             lgr.error(er);lgr.error('Exit and try creating socket again')
             #traceback.print_exc() --not
             time.sleep(1.0);sys.exit(1) 

#-------------------------------------------------------------------------------------------------------#
# Class for read pcap file in csv file 
# Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False
# scan  function support for pcap file
# filtered_pcap="filtered.pcap"
# mod_file_response='filter_resp.pcap'
# mod_file_request='filter_reg.pcap'  
#-------------------------------------------------------------------------------------------------------#
class black_box_pcap(object):
        
    def __init__(self,csvFile="search.csv" ,pcap_file="packets.pcap",filtered_pcap="filtered.pcap",mod_file_response='filter_resp.pcap',mod_file_request='filter_req.pcap' ):              
        """
        
        @param csvFile:            search.csv, file to save FC and address results of search 
        @param pcap_file           reads a pcap file
        @param filtered_pcap       save in filtered.pcap/request and response
        @param mod_file_response   parsing/ scapy library/mod_file_response=filter_resp.pcap
        @param mod_file_request    parsing/ scapy library/mod_file_response=filter_req.pcap 
        
        @type        int

        @param list_csv            Add to clobal list the return list/list of list
        
        """

        self.csvFile=csvFile
        self.pcap_file=pcap_file
        self.filtered_pcap=filtered_pcap
        self.list_csv=[]
        self.mod_file_response=mod_file_response
        self.mod_file_request=mod_file_request 


    def con_SUT_pcap (self):
            """global forever,search_mode,csvFile,pcap_file,filtered_pcap,mod_file_response,mod_file_request,""" 
                       
            try:
                l2=[]                                      
                lgr.info('\n \t \t Verifies which function codes are supported  .....')                 
                l1=self.get_pkt(self.pcap_file)                               
                #Add to clobal list the return list/list of list
                self.list_csv.append(l1)
                self.list_csv.append(l2)                            
                # mapping address table    
                lgr.info('mapping address table ....')               
                l3,l4,l5,l6=self.getadd_pcap(self.filtered_pcap)
                #case empty list / the SUT not response in address/return empty address list
                if len(l3) == 0:
                    l3=[0,65535]
                if len(l4)==0  : 
                    l4=[0,65535]
                if len(l5) == 0:
                    l5=[0,65535]
                if len(l6) == 0:
                    l6=[0,65535]       

                self.list_csv.append(l3)
                self.list_csv.append(l4)
                self.list_csv.append(l5)
                self.list_csv.append(l6)
                                              
                # Write to csv search results of search  pcap file 
                black_box().WriteCSVFile(self.csvFile,self.list_csv)                                                                                                                                 
            
            except  (KeyboardInterrupt, SystemExit):
                lgr.info("You hit control-c")
                raise           
            
            except Scapy_Exception as msg:
                lgr.error(msg, "Scapy problem ...")
                raise    
            
            except IOError as err:
                lgr.error(err.errno);  lgr.error(err.strerror)
               
            #default/malformed packet
            except  Exception as er:                                                                  
               lgr.error(er);lgr.error('exit and try again')
               #traceback.print_exc()   --not            
               time.sleep(1.0)
                         
            finally:
                lgr.info('Total packets read (reconnaissance): %d', fuzz_session.num_packets)                                     
                lgr.info("Finally! search all DONE !!.")                    
                
    def read_pcap(self,filtered_pcap):
        """
        This function reads a pcap file/filtered_pcap and returns a packet
        """ 

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

    
    def get_pkt(self,pcap_file):
        """
        read packet for pcap file  and  look for supported function codes with scapy
        Bytes literals are always prefixed with 'b' or 'B'; they produce an instance of the bytes type instead of the str type. 
        They may only contain ASCII characters; bytes with a numeric value of 128 or greater must be expressed with escapes.
        """
        supportedFuncCodes = []
        pkt_cn=0      
        lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic from pcap file")
        
        #filter by protocol, ModbusADU
        self.filter_pcap(pcap_file)                            #save in filtered.pcap/request and response
        self.filter_pcap_response(self.filtered_pcap)          #filtered_pcap= filtered.pcap   
        pkts=rdpcap(self.mod_file_response)                    #parsing/ scapy library/mod_file_response=filter_resp.pcap   
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
        lgr.info('\n \t  \t Total packets read: -----> %d '% pkt_cn)                           
        lgr.info('\n \t  \t The Function code supported ')              
        black_box().print_results_blackbox(FC =supportedFuncCodes)      
        return supportedFuncCodes

    def filter_pcap(self,pcap_file):
        """
        filter by protocol, ModbusADU/capture request and response packet Modbus
        do not care about packets, only about layers, stacked one after the other.
        """   
        pkts = rdpcap(self.pcap_file)
        ports = [502]
        lgr.info('packets filtered ...')        
        filtered = (pkt for pkt in pkts if
            TCP in pkt and 
            ((pkt[TCP].sport in ports and pkt.getlayer(ModbusADUResponse) is not None) or (pkt[TCP].dport in ports and pkt.getlayer(ModbusADURequest))))
        wrpcap('filtered.pcap', filtered)   

    def filter_pcap_response(self,filtered_pcap):
        """
        filter by protocol,ModbusADU/capture  response packet Modbus
        do not care about packets, only about layers, stacked one after the other.
        filtered_pcap=filtered.pcap
        """   
        pkts = rdpcap(self.filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...response')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].sport in ports and pkt.getlayer(ModbusADUResponse) is not None))           
        wrpcap(self.mod_file_response, filtered)

    
    def filter_pcap_request(self,filtered_pcap): 
        """  filter by protocol,ModbusADU/capture request packet Modbus"""
        pkts = rdpcap(self.filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...request')
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].dport in ports and pkt.getlayer(ModbusADURequest) is not None))
        wrpcap(self.mod_file_request, filtered)        
    
    def getadd_pcap(self,filtered_pcap):
        """
        from request pdu in pcap file/Decode request
        Verifies which address are supported, Returns a list with accepted address
        list of supported address 
        """                                                  
        supported_address_coil = []
        supported_address_input_reg = []
        supported_address_dist_input = []
        supported_address_hold_reg = []

        #filter by protocol, ModbusADU/create filtered_request.pcap
        self.filter_pcap_request(filtered_pcap) 
        lgr.info("\n \t  \t Looking for supported address")  
        pkts=rdpcap(self.mod_file_request)                                                 #mod_file_request='filter_reg.pcap'
        fuzz_session.num_packets=len(pkts)                                                                                 
       
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
                lgr.info('Detected function_code is % s'  % function_code)                  #return tuple

                if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info('The read_address is %d ' % starting_address) 
                    
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

                # Write File Record  fc 21
                elif function_code == Write_File_record : 
                    lgr.info("Not implemented yet ..." )
                    pass        

                #22 (0x16) Mask Write Register
                elif function_code == Mask_Write_Register :
                    starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                    supported_address_hold_reg.append(starting_address)     
                    lgr.info("Mask Write Register address  "+str(starting_address)+" is supported." )

                #24 (0x18) Read FIFO Queue
                elif function_code == Read_FIFO_queue :
                    starting_address,=struct.unpack(">H", pdu[1:3])
                    supported_address_hold_reg.append(starting_address)
                    lgr.info("Read_FIFO_queue address  "+str(starting_address)+" is supported." ) 
                    
                # 23 /( 0x17) Read_Write_Multiple_Registers
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
            except  Exception as er: 
                lgr.error(er);continue
            
        #finally :
        lgr.info('\n \t \t \t Total packets read: -----> %d' % fuzz_session.num_packets)
                            
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

        lgr.info('\n \t \t \t Check for address  supported/pcap')        
        black_box().print_results_blackbox(COILS=supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
       
        return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg     
                    
