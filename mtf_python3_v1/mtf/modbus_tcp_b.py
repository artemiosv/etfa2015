#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is distributed under GNU LGPL license, 
 Source code for Modbus/TCP fuzzer used for the ETFA 2015
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr 

 Modbus TestKit: Implementation of Modbus protocol in python--modbus-tk-1.0.0 pyserial-3.4

 The modbus_tk simulator is a console application which is running a server with TCP and RTU communication
 It is possible to interact with the server from the command line or from a RPC (Remote Process Call)
"""

import sys, os, time ,datetime
import socket
import threading
import struct
import select
import modbus_tk
import modbus_tk.defines as defines
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk.hooks import *
import socketserver
import utils_b
import modbus_b
from mtf import *
import logging
from modbus_tk.utils import threadsafe_function, flush_socket, to_data


class ModbusInv_MbapError(Exception):
    """Exception raised when the modbus TCP header doesn't correspond to what is expected"""
    def __init__(self, value):
        Exception.__init__(self, value)

class TimoutException(Exception):
    '''A user-defined exception class.'''
    pass

class TcpMaster_b(modbus_tcp.TcpMaster,modbus_b.Master_b):

    def __init__(self,host='localhost',port=502, timeout_in_sec=1.0):
        """Constructor. Set the communication settings""" 
        
        modbus_b.Master_b.__init__(self, timeout_in_sec)    
        modbus_tcp.TcpMaster.__init__(self,host='127.0.0.1',port=502, timeout_in_sec=1.0)
        self._is_opened = False   
        self._sock = None
        self._host = host
        self._port = port        

    def set_timeout_b(self, timeout_in_sec):
        """Change the timeout value"""
        modbus_b.Master_b.set_timeout(self, timeout_in_sec)
        if self._sock:
            self._sock.setblocking(timeout_in_sec>0)
            if timeout_in_sec:
                self._sock.settimeout(timeout_in_sec) 

    def set_keepalive(self,_sock, after_idle_sec=5, interval_sec=3, max_fails=60):
        """Set TCP keepalive on an open socket.
        It activates after 1 second (after_idle_sec) of idleness,
        then sends a keepalive ping once every 3 seconds (interval_sec),
        and closes the connection after 60 failed ping (max_fails), or 180 seconds
        """
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
            

    def _do_open_b(self):
        """
        add for keepalive, 
        lgr.info('Socket keepalive already on')   
        """
        if self._sock:
            self._sock.close()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_keepalive(self._sock)
        self.set_timeout_b(self.get_timeout())
        x= self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
        if (x==0):
            lgr.info('Socket keepalive off, turning on');self.set_keepalive(self._sock)    
        else:pass 
       
        call_hooks("modbus_tcp.TcpMaster.before_connect", (self, ))       
        self._sock.connect((self._host, self._port))
        call_hooks("modbus_tcp.TcpMaster.after_connect", (self, )) 

  
    def _recv_b(self, expected_length=-1):                               
        """
        Add for fuzzer -Receive the response from the slave-
        
        """
        response = to_data('')                                                     
        length = 255
        
        while len(response)<length:
            
            try:
            # read at most 1 bytes 
                rcv_byte = self._sock.recv(1)            
               
            except socket.timeout:                
                lgr.error('Socket timeout..  not receive')
                if fuzz_session.receive_flag==False :
                        fuzz_session.receive_timeout=1   
                        fuzz_session.receive_flag=True #enable counter
                        fuzz_session.init_num_rec=fuzz_session.num_of_request
                #i already have a measurement, i look if it is continuous, socket_flag==False
                elif (fuzz_session.num_of_request-1 == fuzz_session.init_num_rec) and (fuzz_session.receive_timeout!=15):                                   
                        fuzz_session.receive_timeout += 1
                        fuzz_session.init_num_rec=fuzz_session.num_of_request
                        
                        if fuzz_session.receive_timeout==15 : 
                            fuzz_session.receive_flag=False;lgr.info('')                           
                            lgr.warn('Connection not response (timeout) after %d request..Connection lost/freeze..do open new connection'%fuzz_session.receive_timeout);time.sleep(5.0)                                                                                                         
                            fuzz_session.receive_timeout=0
                            self._do_open_b()
                            
                else:
                    fuzz_session.receive_flag=False
                return response  

            
            except socket.error as e:                               
                lgr.error("Socket Error: %s ", (e))                
                return response 
                continue                           

            if rcv_byte:
                response += rcv_byte                         
                if len(response) == 6:
                    (tr_id, pr_id, to_be_recv_length) = struct.unpack(">HHH", response)  
                    length = to_be_recv_length + 6
            else:
                break
                
        retval = call_hooks("modbus_tcp.TcpMaster.after_recv", (self, response))
        if retval != None:
            return response
        return response       
    
    def _send_b(self, request):
        
        retval = call_hooks("modbus_tcp.TcpMaster.before_send", (self, request))
        if retval != None:
            request = retval
        try:
            utils_b.flush_socket_b(self._sock, 3)

        except Exception as msg:
            #if we can't flush the socket successfully: a disconnection may happened
            #try to reconnect                       
            self._do_open_b()
        if len(request)>260:
            lgr.error('total len request out of specifications .. !! : %d bytes' % len(request))    
        else :
            lgr.info('total len request : %d bytes' % len(request))
        self._sock.send(request)    
        

class TcpServer_b(modbus_tcp.TcpServer,modbus_b.Server_b,modbus_b.Databank_b):
    """This class implements a simple and mono-threaded modbus tcp server"""
    
    def __init__(self,port=502, address='localhost', timeout_in_sec=5, databank=None):
        """Constructor: initializes the server settings"""
        
        modbus_b.Server_b.__init__(self,databank if databank else modbus_b.Databank_b())
        self._sock = None
        self._sa = (address, port)
        self._timeout_in_sec = timeout_in_sec
        self._sockets = []


    def _do_run_b(self):
        """called in a almost-for-ever loop by the server
           check the status of every socket
        """
        inputready, outputready, exceptready = select.select(self._sockets, [], [], 1.0)

        for sock in inputready: 
            try:
                if sock == self._sock:
                    # handle the server socket
                    client, address = self._sock.accept()
                    client.setblocking(0)
                    lgr.info("%s is connected with socket %d..." % (str(address), client.fileno()))
                    self._sockets.append(client)
                    call_hooks("modbus_tcp.TcpServer.on_connect", (self, client, address))
                else:
                    if len(sock.recv(1, socket.MSG_PEEK)) == 0:
                        #socket is disconnected
                        lgr.info("%d is disconnected" % (sock.fileno()))
                        call_hooks("modbus_tcp.TcpServer.on_disconnect", (self, sock))
                        sock.close()
                        self._sockets.remove(sock)
                        break
                    
                    # handle all other sockets
                    sock.settimeout(1.0)
                    request = to_data("")
                    is_ok = True
                    
                    #read the 7 bytes of the mbap
                    while (len(request) < 7) and is_ok: 
                        new_byte = sock.recv(1)
                        if len(new_byte) == 0:
                            is_ok = False    
                        else:
                            request += new_byte
                        
                    retval = call_hooks("modbus_tcp.TcpServer.after_recv", (self, sock, request))
                    if retval != None:
                        request = retval
                    
                    if is_ok:
                        #read the rest of the request
                        length = self._get_request_length(request)
                        while (len(request) < (length + 6)) and is_ok:
                            new_byte = sock.recv(1)
                            if len(new_byte) == 0:
                                is_ok = False
                            else:
                                request += new_byte 
                    
                    if is_ok:
                        response = ""
                        #parse the request
                        try:
                            response = self.handle_b(request)       
                        except Exception as msg:
                            lgr.error("Error while handling a request, Exception occurred: %s", msg)
                        
                        #send back the response
                        if response:
                            try:
                                retval = call_hooks("modbus_tcp.TcpServer.before_send", (self, sock, response))
                                if retval != None:              
                                    response = retval
                                total_sent=0                                
                                sock.send(response)
                            except Exception as msg:
                                is_ok = False
                                lgr.error("Error while sending on socket %d, Exception occurred: %s", \
                                             sock.fileno(), msg)
            except Exception as excpt:
                lgr.warning("Error while processing data on socket %d: %s", sock.fileno(), excpt)
                call_hooks("modbus_tcp.TcpServer.on_error", (self, sock, excpt))
                sock.close()
                self._sockets.remove(sock)

#---------------------------------------------------- ------------------------------------
# add for fuzzer
#------------------------------------------------------------------------------------------
class TcpMbap_b(modbus_tcp.TcpMbap):
    """Defines the information added by the Modbus TCP layer"""
    
    def __init__(self):
        """Constructor: initializes with 0"""
        self.transaction_id = 0
        self.protocol_id = 0
        self.length = 0
        self.unit_id = 0

    def pack(self):
        """convert the TCP mbap into a string"""
        return struct.pack(">HHHB", self.transaction_id, self.protocol_id, self.length, self.unit_id)
        
    def unpack(self, value):
        """extract the TCP mbap from a string"""
        (self.transaction_id, self.protocol_id, self.length, self.unit_id) = struct.unpack(">HHHB", value)    #python 3 fix .encode() 

    # Check that the MBAP of the response is valid. If not write log error /add for fuzzer dessect message
    def check_response_b(self, request_mbap, response_pdu_length):
        """Check that the MBAP of the response is valid. If not write log error"""
        
        error_str = self._check_ids(request_mbap)
        error_str += self.check_length(response_pdu_length)
        if len(error_str)>0:
            #raise ModbusInvalidMbapError, error_str
            lgr.error('ModbusInvalidMbapError %r.' % (error_str))    

class TcpQuery_b(modbus_tcp.TcpQuery,modbus.Query):
    """Subclass of a Query. Adds the Modbus TCP specific part of the protocol"""    
    
    last_transaction_id = 0
    
    def __init__(self):
        """Constructor"""
        
        modbus.Query.__init__(self)
        self._request_mbap = TcpMbap_b()
        self._response_mbap = TcpMbap_b()

    def get_transaction_id_b(self):
        """returns an identifier for the query"""
        if TcpQuery_b.last_transaction_id < 0xffff:
            TcpQuery_b.last_transaction_id += 1
        else:
            TcpQuery_b.last_transaction_id = 0
        return TcpQuery_b.last_transaction_id
        
    #---------------------------------------------------------------------------------------------
    # process the fuzzer
    # static variable for giving a unique id to each query/ first self._request_mbap without fuzzer
    #--------------------------------------------------------------------------------------------    
    def build_request_b(self,pdu,slave):
        """Add the Modbus TCP part to the request"""

        adu=""
        p=process()
        self._request_mbap.length = len(pdu)+1 
        self._request_mbap.transaction_id = self._get_transaction_id() 
        self._request_mbap.unit_id = slave
        self._request_mbap.protocol_id = 0                
        adu,pdu=p.init_new_session(pdu,slave)             # Call the fuzzing mode and fuzz testing 
       
        
        if adu=="":                                       #no fuzzing adu
           mbap = self._request_mbap.pack()               #pack to string
           return mbap+ pdu                               #to return to modbus_b.py def executed. pdu byte odject
        else :
           self._request_mbap.unpack(adu)                 #fuzz instanse mbap /for  response_mbap.check_response_b                                     # 
           return adu+pdu                                 # string fields, return to modbus_b.py def executed    
                
    
    def parse_request_b(self, request):
        """Extract the pdu from a modbus request"""
        
        if len(request) > 6:
            mbap, pdu = request[:7], request[7:]
            self._request_mbap.unpack(mbap)
            self._request_mbap.transaction_id    
            self._request_mbap.unit_id
        else:
            lgr.warn("Request length is only %d bytes. " % (len(request)))

    
    def parse_response_b(self, response):                                        
        """Extract the pdu from the Modbus TCP response,add for fuzzer and black box"""
        if len(response) > 6:
            mbap, pdu = response[:7], response[7:]
            self._response_mbap.unpack(mbap)
            self._response_mbap.check_response_b(self._request_mbap, len(pdu)) # check mbap and write log/ for fuzzer dissect
            return pdu
        else:
            lgr.warn('ModbusResponseError  length is only %d bytes.' % len(response))
            return response

    def build_request_blackbox(self, pdu, slave):
        """Add the Modbus TCP part to the request, return bytearray (python3)"""
        if (slave < 0) or (slave > 255):
            raise InvalidArgumentError("%d Invalid value for slave id" % (slave))
        self._request_mbap.length = len(pdu)+1
        self._request_mbap.transaction_id = self._get_transaction_id()
        self._request_mbap.unit_id = slave
        mbap = self._request_mbap.pack()
        return mbap+pdu                                

        
        
                