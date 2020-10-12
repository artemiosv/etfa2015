#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
his is distributed under GNU LGPL license, 
 Source code for Modbus/TCP fuzzer used for the ETFA 2015
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr

 Modbus TestKit: Implementation of Modbus protocol in python--modbus-tk-1.0.0 pyserial-3.4 
 
 The modbus_tk simulator is a console application which is running a server with TCP and RTU communication
 It is possible to interact with the server from the command line or from a RPC (Remote Process Call)
"""

import sys, os, time,datetime
import struct
import threading
import modbus_tk
import modbus_tk.defines as defines
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk.hooks import *
import queue
import socketserver
import ctypes
import modbus_tk.utils 
from modbus_tk.utils import threadsafe_function
from utils_b import *
import scapy.layers.l2
import scapy.layers.inet
from scapy.all import *
from message import *
from mtf import *


DUFF=False
fuzz_session = Fuzz_session()

class ModbusError(Exception):
    """Exception raised when the modbus slave returns an error"""
    
    def __init__(self, exception_code, value=""):
        """constructor: set the exception code returned by the slave"""
        if not value:
            value = "Modbus Error: Exception code = %d" % (exception_code)
        Exception.__init__(self, value)
        self._exception_code = exception_code
        
    def get_exception_code(self):
        """return the exception code returned by the slave (see defines ON TOP )"""
        return self._exception_code

class FunctionNotSupportedError(Exception):
    """
    Exception raised when calling a modbus function not supported by modbus_tk
    """
    
    pass

class ModbusInvalidResponseError(Exception):
    """
    Exception raised when the response sent by the slave doesn't fit 
    with the expected format
    """    
    pass   
          
        
class Master_b(modbus.Master):
    """
    This class implements the Modbus Application protocol for a master
    To be subclassed with a class implementing the MAC layer
    """

    def __init__(self,timeout_in_sec, hooks=None):
        """Constructor"""
        modbus.Master.__init__(self,timeout_in_sec,hooks=None)

    # add for fuzzer
    def open_b(self):
        """open the communication with the slave"""
        if not self._is_opened:
            self._do_open_b()
            self._is_opened = True    

    def _send_b(self, buf):
        """Send data to a slave on the MAC layer"""
        raise NotImplementedError()    

    """ Add for send pdu and response pdu return / use black-box/not fuzz/""" 
    @threadsafe_fun
    def execute_master(self,slave,pdu,expected_length=-1):
        
        query = modbus_tcp_b.TcpQuery_b()
        request = query.build_request_blackbox(pdu, slave)  
        lgr.info('request pdu: ---> %r '% ByteToHex(pdu))

        # send the request to the slave
        retval = call_hooks("modbus.Master.before_send", (self,request))

        if retval != None:
            request = retval
           
        if self._verbose:
            lgr.warn(utils.get_log_buffer("-> ", request))
        self._send_b(request)

        call_hooks("modbus.Master.after_send", ())
       
        if slave != 0:
        # receive the data from the slave server
            response = self._recv_b(expected_length)
            retval = call_hooks("modbus.Master_b.after_recv", (self, response))
            if retval != None:
                response = retval
                
            if self._verbose:
                lgr.warn(utils.get_log_buffer("<- ", response))
            # extract the pdu part of the response
            response_pdu = query.parse_response_b(response)
           
        return response_pdu 

    

    """Add for  memory dump attacks  implementation  Execute a modbus query and returns the data part of the answer """ 
    
    def execute_read_memory(self, slave, function_code, address_read, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            """
            import fuzz_session                                       
            pdu = ""
            request=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            #Build the modbus pdu and the format of the expected data.
            #It depends of function code. see modbus specifications for details.
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                byte_count = quantity_of_x //8
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:                   #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5      #slave + func + bytcodeLen + bytecode + crc1 + crc2

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5  #slave + func + bytcodeLen + bytecode x 2 + crc1 + crc2                 
           
            else:
                lgr.warn('The %d function code is not supported.' % function_code)
                pass
            
            if (fuzz_session.search_mode==True) and (fuzz_session.fuzz_mode==False):                             # search False /fuzzer mode
                """for fuzzer object"""  
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)                                                                      
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval != None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                             #in modbus_tcp_b 
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval != None:
                        response = retval
                    if self._verbose:
                        lgr.warn(utils.get_log_buffer("<- ", response))
                    lgr.info('Fuzzing_address %s, response Modbus message : %r' % (address_read, ByteToHex(response)))
                     
                    if len(response)==0:
                        return response
                    else :                                                
                        response_pdu = query.parse_response_b(response)                           #extract the pdu part of the response
                        
                        """analyze the received data Response message analyzer"""
                        (return_code, byte_2) = struct.unpack(">BB", response_pdu[0:2])
                        if return_code >= 0x80:                   
                                exception_code = byte_2
                                if 1 <= exception_code<= 4:                                       # exception Code out of specifications !!!!
                                    lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                                    #raise ModbusError(exception_code)
                                    return lgr.info('Answer >> First address_read %s response %r '  % (address_read,(return_code, byte_2)))
                                else : 
                                    lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                                    return lgr.info('Answer >> First address_read %s response %r '  % (address_read,(return_code, byte_2)))              

                        elif return_code!= function_code :
                            lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                            return lgr.info('Answer >> First address_read %s response %r '  % (address_read,ByteToHex(response)))              

                        else:
                            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:                               
                                # get the values returned by the reading function
                                data_format = ">"+(byte_count*"B")
                               
                                data = response_pdu[2:]
                                if byte_count != len(data):                 # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.warn("ModbusInvalidResponseError >> Wall_Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.warn('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+(len(data)*"B")      #case  byte_2=0                       
                                    result=""
                                    if len(data) !=0 :
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in range(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return result 
                            
                            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                                #get the values returned by the reading function
                                nb_of_digits=0
                                data = response_pdu[2:]
                                byte_count = byte_2                                   #Response byte count                                
                                                                                            
                                data_format = ">"+((byte_count//2)*"H")
                                                                
                                if len(data) <= 1 :
                                    return lgr.error('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))                         # not register len (16bit)    
                               
                                if byte_count != len(data):                 # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.error("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.error('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+((len(data)//2)*"H")                                                  
                                    result=""
                                    if (len(data)%2)==0 : z=(len(data))                                                    
                                    else : z=(int(len(data))-1)                                    
                                    if len(data) !=0 and len(data) >= 2 :                                        
                                        data = response_pdu[2:2+z]                         # module /2                                             
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in range(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return result

                            # returns what is returned by the slave after a writing function /return tumple (results)                                   
                            
                            #returns the data as a tuple according to the data_format
                            #(calculated based on the function or user-defined)
                            result = struct.unpack(data_format, data)
                            if nb_of_digits > 0:
                                digits = []
                                for byte_val in result:
                                    for i in range(8):
                                        if (len(digits) >= nb_of_digits):
                                            break
                                        digits.append(byte_val % 2)
                                        byte_val = byte_val >> 1
                                result = tuple(digits)
                                                                
                            return result
                        
            else  :
                lgr.error('Problem')
                return       

    """Add for implementation  Define function code Modbus_tk for use to fuzzer/Execute a modbus query and returns the data part of the answer """ 
 
    def execute_f(self, slave, function_code, starting_address, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            Build the modbus pdu and the format of the expected data.
            It depends of function code. see modbus specifications for details.
            """
            import fuzz_session                             #insert fuzz_session.fuzz_mode, fuzz_session.search_mode          
            pdu = ""
            reguest=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                byte_count = quantity_of_x // 8
                
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5  

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5  

            elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER):
                if function_code == defines.WRITE_SINGLE_COIL:
                    if output_value != 0:
                        output_value = 0xff00
                pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                     #No lenght was specified and calculated length can be used:
                    expected_length = 8                      

            elif function_code == WRITE_MULTIPLE_COILS:
                byte_count = len(output_value) // 8
                if (len(output_value) % 8) > 0:
                    byte_count += 1
                pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count)
                i, byte_value = 0, 0
                for j in output_value:
                    if j > 0:
                        byte_value += pow(2, i)
                    if i == 7:
                        pdu += struct.pack(">B", byte_value)
                        i, byte_value = 0, 0
                    else:
                        i += 1
                if i > 0:
                    pdu += struct.pack(">B", byte_value)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                         #No lenght was specified and calculated length can be used:
                    expected_length = 8                         

            elif function_code == WRITE_MULTIPLE_REGISTERS:
                byte_count = 2 * len(output_value)
                pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count)
                for j in output_value:
                    pdu += struct.pack(">H", j)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                         #No lenght was specified and calculated length can be used:
                    expected_length = 8                                           
           
            else:
                lgr.warn('The %d function code is not supported.' % function_code)
                pass
               
                         
            """for mapping address"""
            if  (fuzz_session.search_mode== True) and (fuzz_session.fuzz_mode==False):      #black box search
            
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)                                                       
                # send the request to the slave
                lgr.info('The request Modbus message : %r ' % ByteToHex(request))           #request  to SUT
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval != None:
                    request = retval
                   
                if self._verbose:
                    lgr.warn(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                                                       #self._send_b(request)-->>>in modbus_tcp_b
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval != None:
                        response = retval
                    if self._verbose:
                        lgr.warn(utils.get_log_buffer("<- ", response))
                    # extract the pdu part of the response
                    response_pdu = query.parse_response_b(response)
                    
                return response_pdu          
             
            elif (fuzz_session.search_mode==False) and (fuzz_session.fuzz_mode==True):                             # search False /fuzzer mode
                """for fuzzer object"""  
                query = modbus_tcp_b.TcpQuery_b()                                                                  # my object for fuzzer                               
                request = query.build_request_b(pdu, slave)                                                        # request for fuzzer                                          
                lgr.info('The request Modbus message first 260 ByteHex : %r ' % ByteToHex(request[:260]))           #Fuzz request  to SUT                                                      
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval != None:
                    request = retval
                   
                if self._verbose:
                    lgr.warn(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                                                                                #in modbus_tcp_b 
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval != None:
                        response = retval
                    if self._verbose:
                        lgr.warn(utils.get_log_buffer("<- ", response))
                    #all case response Modbus message 
                    lgr.info('Fuzzing_address %s, response Modbus message : %r' % (starting_address, ByteToHex(response)))    
                    # extract the pdu part of the response
                    if len(response)==0 :
                        lgr.critical('Fuzzing_address %s, response Modbus message : %r' % (starting_address, ByteToHex(response)))                                                                               
                        return response
                    else :         
                    #extract the pdu part of the response                    
                        response_pdu = query.parse_response_b(response)
                        if len(response_pdu)==1 or len(response_pdu)==0 : 
                            lgr.critical('Fuzzing_address %s, response Modbus message : %r' % (starting_address, ByteToHex(response)))                                                                               
                            return response
                        """analyze the received data Response message analyzer byte >=2"""
                        (return_code, byte_2) = struct.unpack(">BB", response_pdu[0:2])
                        if return_code >= 128:                   
                                exception_code = byte_2
                                if 1 <= exception_code<= 4:                                       # exception Code out of specifications !!!!
                                    lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                                    #raise ModbusError(exception_code)
                                    return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,(return_code, byte_2)))
                                else : 
                                    lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                                    return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,(return_code, byte_2)))              

                        elif return_code!= function_code :
                            lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                            return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,ByteToHex(response)))              

                        else:
                            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:                               
                                # get the values returned by the reading function
                                data_format = ">"+(byte_count*"B")
                               
                                data = response_pdu[2:]
                                if byte_count != len(data):                            # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.warn("ModbusInvalidResponseError >> Wall_Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.warn('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+(len(data)*"B")                      # if  byte_2==0                       
                                    result=""
                                    if len(data) !=0 and len(data) >= 2 :
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in range(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return lgr.error('Answer >> Fuz_address %s result  %r '  % (starting_address,result)) 
                            
                            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                                #get the values returned by the reading function
                                nb_of_digits=0
                                data = response_pdu[2:]
                                byte_count = byte_2                                            #response byte count                                                                                                                           
                                data_format = ">"+((byte_count//2)*"H")
                                
                                if len(data) <= 1 :
                                    return lgr.error('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))                         # not register len (16bit)    
                               
                                if byte_count != len(data):                                   # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.error("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.error('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+((len(data)//2)*"H")                                                  
                                    result=""
                                    if (len(data)%2)==0 : z=(len(data))                                                    
                                    else : z=(int(len(data))-1)                                                                                                             
                                    if len(data) !=0 and len(data) >= 2 :                                          
                                        data = response_pdu[2:2+z]                             # module /2  1 byte 
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in range(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return lgr.error('Answer >> Fuz_address %s result  %r '  % (starting_address,result)) 

                            # returns what is returned by the slave after a writing function /return tumple (results)                                   
                            elif (function_code == WRITE_MULTIPLE_REGISTERS) or (function_code == WRITE_MULTIPLE_COILS) : 
                                nb_of_digits=0
                                data = response_pdu[5:] #fix from 3
                                byte_data=len(data)
                                (Quantity_of_Registers, ) = struct.unpack(">H", pdu[3:5])        # 2 BYTE   MAX 1968 COIL/ 123 REG
                                
                                data_format = ">"+((byte_data//2)*"H")
                                if  len(data) ==0 or len(data) < 2 :
                                     return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                #if  return_code  bad 
                                else :
                                    if (return_code == WRITE_MULTIPLE_REGISTERS) or (return_code == WRITE_MULTIPLE_COILS):                                                                              
                                        if (len(data)%2)==0 : z=(len(data))                    #python3                                
                                        else : z=(int(len(data))-1)
                                        data = response_pdu[5:5+z]    
                                        
                                    else :
                                        return lgr.error('ModbusInvalidResponseError/bad code ?  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))                                
                               
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    result = struct.unpack(data_format, data)
                                    if nb_of_digits > 0:
                                        digits = []
                                        for byte_val in result:
                                            for i in range(8):
                                                if (len(digits) >= nb_of_digits):
                                                    break
                                                digits.append(byte_val % 2)
                                                byte_val = byte_val >> 1
                                        result = tuple(digits)                                         #tuple, coil write N*2H
                                       
                                    #compare byte count request/and  quantity of coil/register to write
                                    # convert Tuple to Integer-int(''.join(map(str,result))
                                    if Quantity_of_Registers !=  int(''.join(map(str,result))) :        
                                        return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,Quantity of Registers  %d ,data %r '  % (starting_address,Quantity_of_Registers , result ))
                                    else : 
                                        return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,result))
                                    
                            elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER) :
                                 nb_of_digits=0
                                 data = response_pdu[1:]
                                 byte_data=len(data)                                 
                                 data_format = ">"+((byte_data//2)*"H")

                                 if  len(data) !=0 and len(data) < 4 :                                       #bad output value
                                     return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                #if  return_code  bad
                                 else :
                                    if (return_code == WRITE_SINGLE_COIL) or (return_code == WRITE_SINGLE_REGISTER) :
                                        if (len(data)%2)==0 : z=(len(data))                                                
                                        else : z=(len(data)-1)
                                        data = response_pdu[1:1+z] 
                                        pass

                                    else :
                                        return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                
                            else:   
                                return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))

                            #returns the data as a tuple according to the data_format
                            #(calculated based on the function or user-defined)
                            #data_format=">HH"                                      
                            result = struct.unpack(data_format, data)
                            if nb_of_digits > 0:
                                digits = []
                                for byte_val in result:
                                    for i in range(8):
                                        if (len(digits) >= nb_of_digits):
                                            break
                                        digits.append(byte_val % 2)
                                        byte_val = byte_val >> 1
                                result = tuple(digits)                                
                            return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,result))                        
            else  :
                lgr.error('Problem')
                return    


    """ Add for use  new Function  for fuzzer ,eg Read Fifo Queue,import from message.py , """ 
    def execute_fpdu(self,slave,pdu,expected_length=-1):
                """for fuzzer object, instantiate a query which implements the MAC (TCP or RTU) part of the protocol"""                
                
                query = modbus_tcp_b.TcpQuery_b()                                                             # my object for fuzzer                               
                request = query.build_request_b(pdu, slave)                                                   # request for fuzzer /return mbap+pdu                     
                response_pdu=''                    
                lgr.info('The request Modbus message first 260 ByteHex : %r ' % ByteToHex(request[:260]))     #Fuzz request  to SUT                                             
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval != None:
                    request = retval
                   
                if self._verbose:
                    lgr.warn(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                                                                           #in modbus_tcp_b
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval != None:
                        response = retval
                    if self._verbose:
                        lgr.warn(utils.get_log_buffer("<- ", response))                        
                    # extract the pdu part of the response
                    if len(response)==0:
                       lgr.critical('response Modbus message : %r' % (ByteToHex(response)))
                       return response
                    else :
                        lgr.info('response Modbus message : %r' % ByteToHex(response))
                        response_pdu = query.parse_response_b(response)                                               
                        return self.dissect(pdu,request,response_pdu)   
                            
    
                                                   
    def dissect(self,pdu,request,response_pdu) :
                """  analyze the received data of function 20,21,22,23,24 
                    pdu is first gen not fuzzing,request is fuzzing mbap+pdu
                    extract the pdu part of the response 
                """   
                                                  
                nb_of_digits =0
                is_read_function = True
                data_format = ">HH" 

                (function_code,)=struct.unpack('>B', pdu[0:1])
                
                if len(response_pdu)<2:
                    lgr.critical("ModbusError(not specifications)!! >>return_code and exception Code bad %r" %ByteToHex(response_pdu))
                    if len(response_pdu)==0:return response_pdu
                    (return_code,)=struct.unpack(">B", response_pdu[0:1])
                    return (return_code,)                 
                else :
                    (return_code,byte_2) = struct.unpack(">BB", response_pdu[0:2])       #extract to tumple               
                # analyze the received data                
                if return_code >= 128:                   
                    exception_code = byte_2
                    if 1 <= exception_code<= 4  :                                       # exception Code out of specifications !!!!
                        lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                        #raise ModbusError(exception_code)
                        return (return_code, byte_2)
                    else : 
                        lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                        return (return_code, byte_2)                    
                
                if return_code!= function_code :
                    lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                    return (return_code,function_code)


                #24 (0x18) Read FIFO Queue-Test that the read fifo queue response can decode '''
                #The function returns a
                #count of the registers in the queue, followed by the queued data.
                #Up to 32 registers can be read: the count, plus up to 31 queued data registers.
                #FIFO count <=31, bad len >2x32+2+2              
                #message = byte count+ FIFO count+data
                #handle  = ReadFifoQueueResponse([1,2,3,4])
                #handle.decode(message)
                #return list of value [1,2,3,4]
                
                elif return_code== Read_FIFO_queue:                                                            
                    data = response_pdu[1:]

                    if len(data) <4 :                                                  #bad len response   
                        lgr.warn("Bad len response PDU < 4, FIFO Value Register=error, data %r" %data)                       
                        return data
                    else :    
                        handle  = ReadFifoQueueResponse()
                        message = handle.decode(data)                                          
                        return message                                                                       
                
                elif return_code== Read_File_record:
                     data = response_pdu[1:]                      
                     
                     if len(data)>252 or len(data)<7 :                                 #bad len response legal PDU=253 bytes                                     
                         lgr.error('response malformed packet, invalid PDU len :%d ' %len(response_pdu))
                         return data
                     
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data 
                     
                     else : 
                         handle  = ReadFileRecordResponse()                             
                         message=handle.decode(data)                                          
                         return message 
                    
                elif return_code== Write_File_record :                                  
                     data = response_pdu[1:]
                     if len(data)>245 :
                         lgr.warn("Bad len response packet >245 >%r " %data)
                         return data 
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data  
                     elif pdu == response_pdu :                                    #compare pdu and response_pdu /look >>??? (pdu is fuzz)
                         handle  = WriteFileRecordResponse()                       #respone is ok     
                         records=handle.decode(data)                                                                                                                       
                     else:                                                         #compare len(record_data) and response record_data for groups
                         return data                                                                                                      
                   
                #23 (0x17)-The normal response contains the data from the group of registers that were read.         
                elif return_code== Read_Write_Multiple_Registers:
                    data = response_pdu[2:]
                    byte_data=len(data)                    
                    (Read_Byte_Coun, ) = struct.unpack(">H", pdu[3:5])            #extract to tumple / read byte count request                   
                   
                    if Read_Byte_Coun == (byte_2 //2):

                        if byte_2 == byte_data :                                  # diff from to byte_count/data
                            data_format = ">"+((byte_2//2)*"H")                    #no problem 
                        else :  
                            data_format = ">"+((byte_data//2)*"H")
                            lgr.error("ModbusError(not specifications)!! >>Byte Count=%d- Quantity to Read(byte_data) =%d" % (byte_2 , byte_data))

                        result = struct.unpack(data_format, data)
                    
                    else :
                        # request Read Byte Count not equal response Byte Count/2
                        data_format = ">"+((byte_data//2)*"H")
                        lgr.error("ModbusError(not specifications)!! >>request_Read_Byte_Coun(2*Quantity)=%d- Quantity to read=%d" % (Read_Byte_Coun , byte_2 //2))
                            
                    result = struct.unpack(data_format, data)    
                    
                    if nb_of_digits > 0:
                        digits = []
                        for byte_val in result:
                            for i in range(8):
                                if (len(digits) >= nb_of_digits):
                                    break
                                digits.append(byte_val % 2)
                                byte_val = byte_val >> 1
                        result = tuple(digits)
                        
                    return result
                                                                          
                #22 (0x16)/The normal response is an echo of the request. The response is returned after the register 
                #has been written.            
                elif return_code== Mask_Write_Register :                    
                    data = response_pdu[1:]
                    lgr.info('answer >> message: %r'  % (ByteToHex(data)))
                                      
                    if data != request[8:]:                                              
                       lgr.error("Bad response PDU %r" % ByteToHex(data))
                       return ByteToHex(data) 
                    else  :  
                       return ByteToHex(data)                                   
                
                else:
                    lgr.error("ModbusError(not specifications)!! >>return_code=%d- byte_2=%d" % (return_code, byte_2))   
                    return  
 
class Databank_b(modbus.Databank):
    """A databank is a shared place containing the data of all slaves"""
    
    def __init__(self):
        """Constructor""" 
        modbus.Databank.__init__(self)

    def handle_request_b(self,query,request):
        """
        when a request is received, handle it and returns the response pdu
        """
        request_pdu = ""
        
        try:
            #extract the pdu and the slave id
            (slave_id, request_pdu) = query.parse_request(request)
            #get the slave and let him executes the action
            if slave_id == 0:
                #broadcast
                for key in self._slaves:
                    self._slaves[key].handle_request(request_pdu, broadcast=True)
                return
            else:         
                slave = self.get_slave(slave_id)                
                response_pdu = slave.handle_request(request_pdu)      
                lgr.info('request_pdu : ----->%r' % request_pdu) 
                response = query.build_response(response_pdu)                       #modbus_tcp >build_response(response_pdu) 
                lgr.info("full responce hex")   
                lgr.info("\n----------------------------------------------------------------") 

        except Exception as excpt:
            call_hooks("modbus.Databank.on_error", (self, excpt, request_pdu))
            lgr.error("handle request failed: " + str(excpt))
        except:
            lgr.error("handle request failed: unknown error")


class Server_b(modbus.Server):
    """
    This class owns several slaves and defines an interface
    to be implemented for a TCP or RTU server
    """
    
    """Constructor""" 
    def __init__(self, databank=None):
        modbus.Server.__init__(self,databank)
        #self._databank = databank if databank else Databank() #never use a mutable type as default argument
        self._verbose = False
        self._thread = None
        self._go = None
        self._make_thread_b()
        

    def _make_thread_b(self):
        """create the main thread of the server"""
        self._thread = threading.Thread(target=Server_b.run_server_b, args=(self,))  
        self._go = threading.Event()


    def start_b(self):
        """Start the server. It will handle request"""
        self._go.set()
        self._thread.start()

    def stop_b(self):
        """stop the server. It doesn't handle request anymore"""
        if self._thread.isAlive():
            self._go.clear()
            self._thread.join()

    def run_server_b(self):
        """main function of the main thread"""
        try:
            self._do_init()
            while self._go.isSet():
                
                self._do_run_b()             
            lgr.info("%s has stopped" % self.__class__)
            self._do_exit()
        except Exception as excpt:
            lgr.error("server error: %s" % str(excpt))
        self._make_thread_b() 

    def handle_b(self, request):
        """handle a received sentence"""
             
        if self._verbose:
            lgr.debug(utils.get_log_buffer("-->", request))
        
        #gets a query for analyzing the request
        query = self._make_query()
        retval = call_hooks("modbus.Server.before_handle_request", (self, request))
        if retval:
            request = retval
            
        response = self._databank.handle_request_b(query, request)         
        retval = call_hooks("modbus.Server.after_handle_request", (self, response))
        if retval:
            response = retval
                
        if response and self._verbose:
            lgr.debug(utils.get_log_buffer("<--", response))
        return response
   