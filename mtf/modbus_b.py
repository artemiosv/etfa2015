#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python

 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr

 This is distributed under GNU LGPL license, see license.txt

 The modbus_tk simulator is a console application which is running a server with TCP and RTU communication
 It is possible to interact with the server from the command line or from a RPC (Remote Process Call)
"""

import sys, os, time,datetime

import struct
import threading
import modbus_tk
import modbus_tk.defines as defines
#from modbus_tk.modbus  import *
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk.hooks import *
import Queue
import SocketServer
import ctypes
import modbus_tk.utils 
from modbus_tk.utils import threadsafe_function
from utils_b import *
import scapy.layers.l2
import scapy.layers.inet
from scapy.all import *

from message import *
from mtf import * 

#add logging capability
#LOGGER = logging.getLogger("modbus_tk")
#LOGGER = modbus_tk.utils.create_logger(name="console", record_format="%(message)s")
#logger = modbus_tk.utils.create_logger("console")


DUFF=False
fuzz_session = Fuzz_session()
#-------------------------------------------------------------------------------
#Exceptions/FROM MODBUD_TK
#-------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------
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
    #def __init__(self, response):
    """constructor: set the exception code returned by the slave"""
    #    self._response = response        
        
    pass   
          
        
class Master_b(modbus.Master):
    """
    This class implements the Modbus Application protocol for a master
    To be subclassed with a class implementing the MAC layer
    """

    def __init__(self,timeout_in_sec, hooks=None):
        """Constructor"""
        modbus.Master.__init__(self,timeout_in_sec,hooks=None)

    #prostiki gia fuzzer
    def open_b(self):
        """open the communication with the slave"""
        if not self._is_opened:
            self._do_open_b()
            self._is_opened = True    

    def _send_b(self, buf):
        """Send data to a slave on the MAC layer"""
        raise NotImplementedError()    

    """prostiki for send pdu and response pdu return / use black-box/not fuzz/""" 
    @threadsafe_fun
    def execute_master(self,slave,pdu,expected_length=-1):
        # instantiate a query which implements the MAC (TCP or RTU) part of the protocol        
        #---- add for use only to black-box -------send pdu
        query = modbus_tcp_b.TcpQuery_b()
        request = query.build_request_blackbox(pdu, slave)  
        print 'reguest pdu: -----> %r '% ByteToHex(pdu)
        lgr.info('reguest pdu: ---> %r '% ByteToHex(pdu))

         # send the request to the slave
        retval = call_hooks("modbus.Master.before_send", (self,request))

        if retval <> None:
            request = retval
           
        if self._verbose:
            lgr.debug(utils.get_log_buffer("-> ", request))
        self._send(request)

        call_hooks("modbus.Master.after_send", ())
       
        if slave != 0:
        # receive the data from the slave server
            response = self._recv_b(expected_length)
            retval = call_hooks("modbus.Master_b.after_recv", (self, response))
            if retval <> None:
                response = retval
                
            if self._verbose:
                lgr.debug(utils.get_log_buffer("<- ", response))
            # extract the pdu part of the response
            response_pdu = query.parse_response_b(response)
           
        return response_pdu 

    ####################### Add for memory dump attacks  ###########################################################

    """Add for  memory dump attacks  implementation  Execute a modbus query and returns the data part of the answer -----------""" 
    ################################################################################################################
    def execute_read_memory(self, slave, function_code, address_read, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            """
            import fuzz_session                             #INSERT fuzz_session.fuzz_mode , fuzz_session.search_mode          
            pdu = ""
            reguest=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            #Build the modbus pdu and the format of the expected data.
            #It depends of function code. see modbus specifications for details.
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                byte_count = quantity_of_x / 8
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:               #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5  #slave + func + bytcodeLen + bytecode + crc1 + crc2

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5  #slave + func + bytcodeLen + bytecode x 2 + crc1 + crc2                 
           
            else:
                print >>sys.stderr, 'The %d function code is not supported.' % function_code
                #lgr ...raise ModbusFunctionNotSupportedError("The %d function code is not supported. " % (function_code))
                pass
            
            if (fuzz_session.search_mode==True) and (fuzz_session.fuzz_mode==False):                             # search False /fuzzer mode
                """for fuzzer object"""  
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)                                                                      
                #print 'request: ----->%r' % request                 
                #lgr.info(' request Modbus message : -----> %r ' % ByteToHex(request))           #reguest  to SUT                                                      
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                             #in modbus_tcp_b 
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))
                    #lgr.info(' Fuz_address %s , response Modbus message : ----->%r' % (address_read, ByteToHex(response)))    
                    # extract the pdu part of the response
                    if response=='':
                        return response
                    else :         
                    
                    #extract the pdu part of the response
                        response_pdu = query.parse_response_b(response)
                        
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
                                #byte_count = struct.unpack(">BB", request_pdu[0:2])  fuzz_byte count
                                data_format = ">"+(byte_count*"B")
                               
                                data = response_pdu[2:]
                                if byte_count != len(data):                 # if response byte is reguest 
                                    # the byte count in the pdu is invalid
                                    lgr.warn("ModbusInvalidResponseError >> Wall_Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.warn('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #print >>sys.stderr, 'ModbusInvalidResponseError Fuz_address %r response %r' % (starting_address,response)
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+(len(data)*"B")      #mpori na feri  byte_2=0                       
                                    result=""
                                    if len(data) !=0 :
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    #return lgr.error('Answer >> Fuz_address %s result  %r '  % (address_read,result))
                                    return result 
                            
                            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                                # get the values returned by the reading function
                                #byte_count = struct.unpack(">BB", request_pdu[0:2])  fuzz_byte count
                                nb_of_digits=0
                                data = response_pdu[2:]
                                byte_count = byte_2                                   #RESPONSE byte count                                
                                                                                            
                                data_format = ">"+((byte_count/2)*"H")
                                
                                #data_format = ">"+(((byte_count/2)-((byte_count) % 2))*"H")    #case byte_count not mod 2                                
                                
                                if len(data) <= 1 :
                                    return lgr.error('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))                         # not register len (16bit)    
                               
                                if byte_count != len(data):                 # if response byte is reguest 
                                    # the byte count in the pdu is invalid
                                    lgr.error("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.error('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #print >>sys.stderr, 'ModbusInvalidResponseError Fuz_address %r response %r' % (starting_address,response)
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+((len(data)/2)*"H")                                                  
                                    result=""
                                    z=(len(data)-1)                                    
                                    if len(data) !=0 and len(data) >= 2 :
                                        data = response_pdu[2:2+z]                         # module /2  1 byte apomeni
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    #return lgr.error('Answer >> Fuz_address %s result  %r '  % (address_read,result))
                                    return result

                            # returns what is returned by the slave after a writing function /return tumple (results)                                   
                            
                            #returns the data as a tuple according to the data_format
                            #(calculated based on the function or user-defined)
                            #data_format=">HH"
                            result = struct.unpack(data_format, data)
                            if nb_of_digits > 0:
                                digits = []
                                for byte_val in result:
                                    for i in xrange(8):
                                        if (len(digits) >= nb_of_digits):
                                            break
                                        digits.append(byte_val % 2)
                                        byte_val = byte_val >> 1
                                result = tuple(digits)
                                #lgr.info(' : %r' % (result,))
                                                                
                            #return lgr.info('Answer >> address_read %s response %r '  % (address_read,result))
                            return result
                        
            else  :
                print >>sys.stderr, 'Problem'
                return       

    """Add for implementation  Define function code Modbus_tk for use to fuzzer/Execute a modbus query and returns the data part of the answer -----------""" 
 
    def execute_f(self, slave, function_code, starting_address, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            """
            import fuzz_session                             #INSERT fuzz_session.fuzz_mode , fuzz_session.search_mode          
            pdu = ""
            reguest=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            #Build the modbus pdu and the format of the expected data.
            #It depends of function code. see modbus specifications for details.
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                byte_count = quantity_of_x / 8
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:               #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5  #slave + func + bytcodeLen + bytecode + crc1 + crc2

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5  #slave + func + bytcodeLen + bytecode x 2 + crc1 + crc2

            elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER):
                if function_code == defines.WRITE_SINGLE_COIL:
                    if output_value != 0:
                        output_value = 0xff00
                pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                     #No lenght was specified and calculated length can be used:
                    expected_length = 8                      #slave + func + adress1 + adress2 + value1+value2 + crc1 + crc2

            elif function_code == WRITE_MULTIPLE_COILS:
                byte_count = len(output_value) / 8
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
                    expected_length = 8                          #slave + func + adress1 + adress2 + outputQuant1 + outputQuant2 + crc1 + crc2

            elif function_code == WRITE_MULTIPLE_REGISTERS:
                byte_count = 2 * len(output_value)
                pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count)
                for j in output_value:
                    pdu += struct.pack(">H", j)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                         #No lenght was specified and calculated length can be used:
                    expected_length = 8                         #slave + func + adress1 + adress2 + outputQuant1 + outputQuant2 + crc1 + crc2                  
           
            else:
                print >>sys.stderr, 'The %d function code is not supported.' % function_code
                #lgr ...raise ModbusFunctionNotSupportedError("The %d function code is not supported. " % (function_code))
                pass
               
           
# instantiate a query which implements the MAC (TCP or RTU) part of the protocol/for mapping address        
            """for mapping address"""
            if  (fuzz_session.search_mode== True) and (fuzz_session.fuzz_mode==False):                             #black box search
            
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)
                #print 'request: ----->%r' % request                                                        
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send(request)                                  #  self._send_b(request)-->>>in modbus_tcp_b
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))
                    # extract the pdu part of the response
                    response_pdu = query.parse_response_b(response)
                    
                return response_pdu          
             
            elif (fuzz_session.search_mode==False) and (fuzz_session.fuzz_mode==True):                             # search False /fuzzer mode
                """for fuzzer object"""  
                query = modbus_tcp_b.TcpQuery_b()                                        # my object for fuzzer                               
                request = query.build_request_b(pdu, slave)                              # reguest for fuzzer                                          
                #print 'request: ----->%r' % request                 
                lgr.info(' request Modbus message : -----> %r ' % ByteToHex(request))     #Fuzz reguest  to SUT                                                      
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                             #in modbus_tcp_b 
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))
                    lgr.info(' Fuz_address %s , response Modbus message : ----->%r' % (starting_address, ByteToHex(response)))    
                    # extract the pdu part of the response
                    if response=='':
                        return response
                    else :         
                    #extract the pdu part of the response
                    
                        response_pdu = query.parse_response_b(response)
                        
                        """analyze the received data Response message analyzer"""
                        (return_code, byte_2) = struct.unpack(">BB", response_pdu[0:2])
                        if return_code >= 0x80:                   
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
                                #byte_count = struct.unpack(">BB", request_pdu[0:2])  fuzz_byte count
                                data_format = ">"+(byte_count*"B")
                               
                                data = response_pdu[2:]
                                if byte_count != len(data):                 # if response byte is reguest 
                                    # the byte count in the pdu is invalid
                                    lgr.warn("ModbusInvalidResponseError >> Wall_Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.warn('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))
                                    #print >>sys.stderr, 'ModbusInvalidResponseError Fuz_address %r response %r' % (starting_address,response)
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+(len(data)*"B")      #mpori na feri  byte_2=0                       
                                    result=""
                                    if len(data) !=0 :
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return lgr.error('Answer >> Fuz_address %s result  %r '  % (starting_address,result)) 
                            
                            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                                # get the values returned by the reading function
                                #byte_count = struct.unpack(">BB", request_pdu[0:2])  fuzz_byte count
                                nb_of_digits=0
                                data = response_pdu[2:]
                                byte_count = byte_2                                   #RESPONSE byte count                                
                                                                                            
                                data_format = ">"+((byte_count/2)*"H")
                                
                                #data_format = ">"+(((byte_count/2)-((byte_count) % 2))*"H")    #case byte_count not mod 2                                
                                
                                if len(data) <= 1 :
                                    return lgr.error('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))                         # not register len (16bit)    
                               
                                if byte_count != len(data):                 # if response byte is reguest 
                                    # the byte count in the pdu is invalid
                                    lgr.error("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.error('Answer >> Fuz_address %s ,fc %d ,response %r '  % (starting_address,return_code, ByteToHex(response)))
                                    #print >>sys.stderr, 'ModbusInvalidResponseError Fuz_address %r response %r' % (starting_address,response)
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+((len(data)/2)*"H")                                                  
                                    result=""
                                    z=(len(data)-1)                                    
                                    if len(data) !=0 and len(data) >= 2 :
                                        data = response_pdu[2:2+z]                         # module /2  1 byte apomeni
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
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
                                data = response_pdu[3:]
                                byte_data=len(data)
                                (Quantity_of_Registers, ) = struct.unpack(">H", pdu[3:5])        # 2 BYTE   MAX 1968 COIL/ 123 REG
                                

                                data_format = ">"+((byte_data/2)*"H")
                                if  len(data) ==0 or len(data) < 2 :
                                     return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                #if  return_code  bad
                                else :
                                    if (return_code == WRITE_MULTIPLE_REGISTERS) or (return_code == WRITE_MULTIPLE_COILS) :
                                        pass
                                    else :
                                        return lgr.error('ModbusInvalidResponseError/bad code ?  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                
                               
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    result = struct.unpack(data_format, data)
                                    if nb_of_digits > 0:
                                        digits = []
                                        for byte_val in result:
                                            for i in xrange(8):
                                                if (len(digits) >= nb_of_digits):
                                                    break
                                                digits.append(byte_val % 2)
                                                byte_val = byte_val >> 1
                                        result = tuple(digits)                                  #tuple, how register/or coil write N*2H
                                       
                                    #compare byte count reguest/and  quantity of coil/register to write
                                    if Quantity_of_Registers !=  int(''.join(map(str,result))) :        # convert Tuple to Integer-int(''.join(map(str,result))
                                        return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,Quantity of Registers  %d ,data %r '  % (starting_address,Quantity_of_Registers , result ))
                                    else : 
                                        lgr.info(' : %d' %  int(''.join(map(str,result))))   
                                        return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,result))
                                    

                            elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER) :
                                 nb_of_digits=0
                                 data = response_pdu[1:]
                                 byte_data=len(data)
                                 
                                 data_format = ">"+((byte_data/2)*"H")

                                 if  len(data) !=0 and len(data) < 4 :              #bad output value
                                     return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                #if  return_code  bad
                                 else :
                                    if (return_code == WRITE_SINGLE_COIL) or (return_code == WRITE_SINGLE_REGISTER) :
                                        pass
                                        #return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))

                                    else :
                                        return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))
                                
                            else:   #return_code  bad
                                return lgr.error('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (starting_address,return_code, ByteToHex(data)))

                            #returns the data as a tuple according to the data_format
                            #(calculated based on the function or user-defined)
                            #data_format=">HH"
                            result = struct.unpack(data_format, data)
                            if nb_of_digits > 0:
                                digits = []
                                for byte_val in result:
                                    for i in xrange(8):
                                        if (len(digits) >= nb_of_digits):
                                            break
                                        digits.append(byte_val % 2)
                                        byte_val = byte_val >> 1
                                result = tuple(digits)
                                lgr.info(' : %r' % (result,))
                                #print >>sys.stderr, 'Fuz_address %r response %r' % (starting_address,result)
                                
                            return lgr.info('Answer >> Fuz_address %s response %r '  % (starting_address,result))
                        
            else  :
                print >>sys.stderr, 'Problem'
                return    


    """ Add for use  new Function  for fuzzer ,eg Read Fifo Queue ,import from message.py , """ 
    def execute_fpdu(self,slave,pdu,expected_length=-1):
                # instantiate a query which implements the MAC (TCP or RTU) part of the protocol
        
                """for fuzzer object"""
                #print 'pdu: ----->%r' % ByteToHex(pdu)
                query = modbus_tcp_b.TcpQuery_b()                                         # my object for fuzzer                               
                request = query.build_request_b(pdu, slave)                               # reguest for fuzzer /return mbap+pdu                     
                response_pdu=''                    
                lgr.info(' request Modbus message : -----> %r ' % ByteToHex(request))     #Fuzz reguest  to SUT                                             
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                                                       #in modbus_tcp_b
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))

                    lgr.info(' response Modbus message : ----->%r' % ByteToHex(response))    
                    # extract the pdu part of the response
                    if response=='':
                       return response
                    else :
                        response_pdu = query.parse_response_b(response)                                               
                        return self.dissect(pdu,response_pdu)   

    """  analyze the received data of function 20.24,21,22,23"""                         

    def dissect(self,pdu,response_pdu) :
                # extract the pdu part of the response
                
                nb_of_digits =0
                is_read_function = True
                data_format = ">HH"
                
                # analyze the received data                
                (return_code, byte_2) = struct.unpack(">BB", response_pdu[0:2])      #extract to tumple
                if return_code >= 0x80:                   
                    exception_code = byte_2
                    if 1 <= exception_code<= 4  :                                       # exception Code out of specifications !!!!
                        lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                        #raise ModbusError(exception_code)
                        return (return_code, byte_2)
                    else : 
                        lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                        return (return_code, byte_2)                    
                
                elif return_code== Read_FIFO_queue:                                  #24 (0x18) Read FIFO Queue                        
                    data = response_pdu[1:]

                    if len(data) <4 :                                               # bad len response   
                        print >>sys.stderr, 'data %r'  % data 
                        lgr.warn("bad len response payload < 4, FIFO Value Register=error ")                       
                        return data
                    else :    
                        handle  = ReadFifoQueueResponse()
                        message = handle.decode(data)                                          
                        return message                                                   
                     
                
                elif return_code== Read_File_record:
                     data = response_pdu[1:]
                     #decode reguest 
                     handle  = ReadFileRecordResponse()
                     records_reg=handle.decode(pdu[1:])                                #list of records
                     print records_reg
                      
                     if len(data)>245 :
                         lgr.warn("bad len response payload >245 >%r " %data)
                         return data 
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data  
                     else : 
                         handle  = ReadFileRecordResponse()                            #decode response in records[]
                         message=handle.decode(data)
                         print message                                                 #compere len(record_data) and reguest record_number
                         return message
                                        

                elif return_code== Write_File_record :                                  
                     data = response_pdu[1:]
                     if len(data)>245 :
                         lgr.warn("bad len response payload >245 >%r " %data)
                         return data 
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data  
                     elif pdu == response_pdu :                                    #compare pdu and response_pdu
                         handle  = WriteFileRecordResponse()                       #respone is ok     
                         records=handle.decode(data)                          
                         #print records                                                
                      
                     else: #compere len(record_data) and response record_data for groups
                         pass
                                                                                                       
                   
                #23 (0x17)-The normal response contains the data from the group of registers that were read.         
                elif return_code== Read_Write_Multiple_Registers:
                    data = response_pdu[2:]
                    byte_data=len(data)                                         #len data response
                    (Read_Byte_Coun, ) = struct.unpack(">H", pdu[3:5])          #extract to tumple / read byte count reguest                   
                   
                    if Read_Byte_Coun == (byte_2 /2):

                        if byte_2 == byte_data :                                 # mporei na exoyn diagoretiko mikos apo oti dixni to byte_count/data
                            data_format = ">"+((byte_2/2)*"H")                   #no problem 
                        else :  
                            data_format = ">"+((byte_data/2)*"H")
                            lgr.error("ModbusError(not specifications)!! >>Byte Count=%d- Quantity to Read(byte_data) =%d" % (byte_2 , byte_data))

                        result = struct.unpack(data_format, data)
                    
                    else :
                        # reguest Read Byte Count not equal response Byte Count/2
                        data_format = ">"+((byte_data/2)*"H")
                        lgr.error("ModbusError(not specifications)!! >>request_Read_Byte_Coun(2*Quantity)=%d- Quantity to read=%d" % (Read_Byte_Coun , byte_2 /2))
                            
                    result = struct.unpack(data_format, data)    
                    if nb_of_digits > 0:
                        digits = []
                        for byte_val in result:
                            for i in xrange(8):
                                if (len(digits) >= nb_of_digits):
                                    break
                                digits.append(byte_val % 2)
                                byte_val = byte_val >> 1
                        result = tuple(digits)
                        print result
                    return result
                                                                          
                #22 (0x16)/The normal response is an echo of the request. The response is returned after the register 
                #has been written.            
                elif return_code== Mask_Write_Register :
                    data = response_pdu[1:]
                    #handle = MaskWriteRegisterResponse()                  #decode int /self.adress,self.and_mask.self.or_mask
                    #handle.decode(data)
                                      
                    if data != request[7:]:
                       #hexdiff(message,p2)
                       lgr.error("bad response payload %r" % ByteToHex(data))
                       return ByteToHex(data) 
                    else  :  
                       return ByteToHex(data)                                    
                
                else:
                    lgr.error("ModbusError(not specifications)!! >>return_code=%d- byte_2=%d" % (return_code, byte_2))   
                    return  

                    
#----------------------------------------------------------------------------------------
 
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
            #print 'slave_id : ----->%r' % slave_id
            #get the slave and let him executes the action
            if slave_id == 0:
                #broadcast
                for key in self._slaves:
                    self._slaves[key].handle_request(request_pdu, broadcast=True)
                return
            else:         
                slave = self.get_slave(slave_id)
                #ayto poy erxete apo scadaBr
                #print 'slave_id_original : ----->%r' % slave_id
                response_pdu = slave.handle_request(request_pdu)      
                print 'request_pdu : ----->%r' % request_pdu
 
                response = query.build_response(response_pdu)      #modbus_tcp >build_response(response_pdu) 
                #print ('response_full in modbus_b.py code: ----->%r ') % response   
#----------------------------------------------------------------                             
                print("full responce hex")   
                print("\n----------------------------------------------------------------") 
# -----------------------------------------------------------------               
                return response
        except Exception, excpt:
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
        self._thread = threading.Thread(target=Server_b.run_server_b, args=(self,))  #allagi
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
                
                self._do_run_b()             #allagi
            lgr.info("%s has stopped" % self.__class__)
            self._do_exit()
        except Exception, excpt:
            lgr.error("server error: %s" % str(excpt))
        self._make_thread_b() #make possible to rerun in future

    def handle_b(self, request):
        """handle a received sentence"""
        
        if self._verbose:
            lgr.debug(utils.get_log_buffer("-->", request))
        
        #gets a query for analyzing the request
        query = self._make_query()
        retval = call_hooks("modbus.Server.before_handle_request", (self, request))
        if retval:
            request = retval
            
        response = self._databank.handle_request_b(query, request)         #allagi
        retval = call_hooks("modbus.Server.after_handle_request", (self, response))
        if retval:
            response = retval
                
        if response and self._verbose:
            lgr.debug(utils.get_log_buffer("<--", response))
        return response
    #------------------------------------------------------------------------