#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback,itertools,struct,logging
from time import * 
import logging.handlers as handlers
import fuzz_session
from add_method  import *
from defines import *
#from module 
from .message import *
from .serial_message import *
from .diag import *

lgr=logging.getLogger('') #create logger-

class TestQueriesSerialFC():
    '''
    Modbus application protocol spec v1.1b3
    This is the test for the pymodbus.diag_message module for Serial//Diagnostics FC
    Diagnostics FC This is the test for the pymodbus.diag_message module for Diagnostics FC
    Diagnostic Function Codes Base Classes diagnostic 08, 00-18,20
    --GetClearModbusPlusResponse, Returns a series of 54 16-bit words (108 bytes) in the data field
    of the response (this function differs from the usual two-byte
    length of the data field). The data contains the statistics for
    the Modbus Plus peer processor in the slave device.


    '''
    def __init__(self):

        self.illegal_pdu_len=[]
        self.start_data=0
        self.step_data=255
        self.end_data=65536
        
    diagnostics= [       
        
        (ReturnQueryDataRequest,                        '\x08\x00\x00\x00\x00'),
        (RestartCommunicationsOptionRequest,            '\x08\x00\x01\x00\x00'),# live the log but priority restart              
        (ReturnDiagnosticRegisterRequest,               '\x08\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterRequest,              '\x08\x00\x03\x00\x00'),
        (ForceListenOnlyModeRequest,                    '\x08\x00\x04\x00\x00'),
        (RestartCommunicationsOptionRequest,            '\x08\x00\x01\x00\x00'),# live the log but priority restart, reset all
        #(RestartCommunicationsclearRequest,             '\x08\x00\x01\xff\x00'),
        (ClearCountersRequest,                          '\x08\x00\x0a\x00\x00'),
        (ReturnBusMessageCountRequest,                  '\x08\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountRequest,       '\x08\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountRequest,           '\x08\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountRequest,                '\x08\x00\x0e\x00\x00'),
        (ReturnSlaveNoResponseCountRequest,             '\x08\x00\x0f\x00\x00'),
        (ReturnSlaveNAKCountRequest,                    '\x08\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountRequest,                   '\x08\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountRequest,    '\x08\x00\x12\x00\x00'),
        (ReturnIopOverrunCountRequest,                  '\x08\x00\x13\x00\x00'),
        (ClearOverrunCountRequest,                      '\x08\x00\x14\x00\x00'),
        (GetClearModbusPlusRequest,                     '\x08\x00\x15\x00\x03'), # GetClearModbusPlus/(Get Statistics) 
        (RestartCommunicationsOptionRequest,            '\x08\x00\x01\xff\x00'), # Com Event Log clear
        (GetClearModbusPlusRequest,                     '\x08\x00\x15\x00\x04'), # GetClearModbusPlus/((Clear Statistics))         
    ]                                                                                   
    

    requests = [
        
        (RestartCommunicationsOptionRequest,            '\x00\x01\x00\x00', '\x00\x01\xff\x00'),
        (ReturnDiagnosticRegisterRequest,               '\x00\x02\x00\x00', '\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterRequest,              '\x00\x03\x00\x00', '\x00\x03\x00\x00'),
        (ForceListenOnlyModeRequest,                    '\x00\x04\x00\x00', '\x00\x04'),
        (ReturnQueryDataRequest,                        '\x00\x00\x00\x00', '\x00\x00\x00\x00'),
        (ClearCountersRequest,                          '\x00\x0a\x00\x00', '\x00\x0a\x00\x00'),
        (ReturnBusMessageCountRequest,                  '\x00\x0b\x00\x00', '\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountRequest,       '\x00\x0c\x00\x00', '\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountRequest,           '\x00\x0d\x00\x00', '\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountRequest,                '\x00\x0e\x00\x00', '\x00\x0e\x00\x00'),
        (ReturnSlaveNoResponseCountRequest,             '\x00\x0f\x00\x00', '\x00\x0f\x00\x00'),  
        (ReturnSlaveNAKCountRequest,                    '\x00\x10\x00\x00', '\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountRequest,                   '\x00\x11\x00\x00', '\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountRequest,    '\x00\x12\x00\x00', '\x00\x12\x00\x00'),
        (ReturnIopOverrunCountRequest,                  '\x00\x13\x00\x00', '\x00\x13\x00\x00'),
        (ClearOverrunCountRequest,                      '\x00\x14\x00\x00', '\x00\x14\x00\x00'),
        (GetClearModbusPlusRequest,                     '\x00\x15\x00\x00', '\x00\x15' + '\x00\x00' * 55),
    ]

    responses = [
        
        (ReturnQueryDataResponse,                      '\x00\x00\x00\x00'),
        (RestartCommunicationsOptionResponse,          '\x00\x01\x00\x00'),
        (ReturnDiagnosticRegisterResponse,             '\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterResponse,            '\x00\x03\x00\x00'),
        (ForceListenOnlyModeResponse,                  '\x00\x04'),
        (ReturnQueryDataResponse,                      '\x00\x00\x00\x00'),
        (ClearCountersResponse,                        '\x00\x0a\x00\x00'),
        (ReturnBusMessageCountResponse,                '\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountResponse,     '\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountResponse,         '\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountResponse,              '\x00\x0e\x00\x00'),
        (ReturnSlaveNoReponseCountResponse,            '\x00\x0f\x00\x00'),
        (ReturnSlaveNAKCountResponse,                  '\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountResponse,                 '\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountResponse,  '\x00\x12\x00\x00'),
        (ReturnIopOverrunCountResponse,                '\x00\x13\x00\x00'),
        (ClearOverrunCountResponse,                    '\x00\x14\x00\x00'),
        (GetClearModbusPlusResponse,                   '\x00\x15' + '\x00\x00' * 55),
    ]

    
    def print_results(self,**kwargs): 
        
        print('                                                                              ', file=sys.stderr)                                                                             
        for name, value in list(kwargs.items()):
            print('{0} = {1}'.format(name, value))
        print('                                                                              ', file=sys.stderr)                                                                              
        return       
    
    # not use-Looking for some  diagnostics for recon, 
    def reconise_diagnostics(self):    
        """ Looking for some  diagnostics for reconiss """
        
        lgr.info('\n \t \t \t ........send  diagnostics..')    
        for msg, enc in self.diagnostics:
            lgr.info('Diagnostics msg : ----->%s ' % msg)
            response_pdu=fuzz_session.master1.execute_master(slave,enc)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        return 

    
    #not use -Looking for supported diagnostics subcodes..      
    def getSupportedsubcodesDiagnostics(self):
        """Looking for supported diagnostics subcodes.."""

        supportedsubDiagnostics = []
        lgr.info('\n \t \t \t ...Looking for supported diagnostics subcodes..') 
        for i in range(21,65535,self.step_data):      
            pdu="\x08"+struct.pack(">H",i)+"\x00\x00"
            response=fuzz_session.master1.execute_fpdu(slave,pdu)                          #return  to tuple
                                                                       
            #analyze the received data Response message analyzer 
            if len(response) >= 2 :                                                       # and len(response[0]) > 1 and response[0][1]:
            #if response:
                return_code=response[0]
                exceptionCode=response[1]
                              
                if return_code >= 128 or exceptionCode == 1 or exceptionCode == 3 or exceptionCode == 4:                 
                    lgr.warn("Sub Diagnostics Code=%r not supported" % (str(i)))
                    #print "Sub Diagnostics Code "+str(i)+" not supported."
                    
                else:
                    supportedsubDiagnostics.append(i)
                    lgr.warn("Sub Diagnostics Code=%r is supported" % (str(i)))
            else:
                lgr.warn("Sub Diagnostics Code=%r probably supported" % (str(i)))
                supportedsubDiagnostics.append(i)

        lgr.info ( '\n----------------supportedsubDiagnostics  --------------')
        self.print_results(response=supportedsubDiagnostics)
        return      

         
    def test_ReadExceptionStatus(self):
        """
        07 (0x07) Read Exception Status (Serial Line only) .
        This function code is used to read the contents of eight Exception Status outputs in a remote device.  
        The function provides a simple method for
        accessing this information, because the Exception Output references are known (no output reference is needed in the function).

        """    
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False : 
                break          
            handle  = ReadExceptionStatusRequest()            
            result = struct.pack(">B",Read_Exception_Status)+handle.encode()
            response=fuzz_session.master1.execute_fpdu(slave,result) 
            lgr.info('answer >>  Output data: %s'  % (response,))
        
        fuzz_session.flag_reguest=True     
        sleep(1.0)         
                
    
    def test_GetCommEventCounter(self):
        '''
        11 (0x0B) Get Comm Event Counter (Serial Line only)
        This function code is used to get a status word and an event count from
        the remote device's communication event counter.
        By fetching the current count before and after a series of messages, a client can determine whether the messages were handled normally by the
        remote device.
        The device's event counter is incremented once  for each successful message completion. It is not incremented for exception responses,
        poll commands, or fetch event counter commands.
        The event counter can be reset by means of the Diagnostics function (code 08), with a subfunction of Restart Communications Option
        (code 00 01) or Clear Counters and Diagnostic Register (code 00 0A)
        '''    
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle  = GetCommEventCounterRequest()           
            result = struct.pack(">B",Get_Comm_Event_Counter)+handle.encode()
            response=fuzz_session.master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))

        fuzz_session.flag_reguest=True      
        sleep(1.0) 
       
        
    def test_GetCommEventLog(self):
        """
        12 (0x0C) Get Comm Event Log (Serial Line only)  
        #This function code is used to get a status word, event count, message count, and a field of event bytes from the remote device.
        #The status word and event counts are identical to that returned by the Get Communications
        #Event Counter function (11, 0B hex). The message counter contains the quantity of messages processed by the remote device
        #since its last restart, clear counters operation, or power–up. This count is identical to that
        #returned by the Diagnostic function (code 08), sub-function Return Bus Message Count (code 11, 0B hex).
        #The event bytes field contains 0-64 bytes, with each byte corresponding to the status of one
        #MODBUS send or receive operation for the remote device. The remote device enters the events into the field in chronological order. 
        #Byte 0 is the most recent event. Each new byte flushes the oldest byte from the field.
        """
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle  = GetCommEventLogRequest()
            result = struct.pack(">B",Get_Comm_Event_Logs)+handle.encode()
            response=fuzz_session.master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))
        fuzz_session.flag_reguest=True
        sleep(1.0)
        
    def test_ReportSlaveId(self):

        """ 17 (0x11) Report Server ID (Serial Line only) 
           This function code is used to read the description of the type, the current status, and other information specific to a remote device.
        """
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle = ReportSlaveIdRequest()
            result = struct.pack(">B",Report_Slave_Id)+handle.encode()
            response=fuzz_session.master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))
        fuzz_session.flag_reguest=True    
        sleep(1.0)

    def test_DiagnosticRequests_data_field(self):
        '''
        This is the test for the pymodbus.diag_message module, for Diagnostics FC
        Diagnostic Function Codes Base Classes
        diagnostic 08, 00-18,20
        Testing diagnostic request messages for all sub_function_code and data field (0,65535)
        >> use in 2-way (pairwise) test subfunction vs data !!!! in case t 3 test PDU fields
        use step prodefine --
        self.start_data=0
        self.step_data=255
        self.end_data=65535

        '''
        for a in itertools.count(): 
            
            for msg,enc in self.diagnostics :
                
                ''' Diagnostic Sub Code 00'''
            
                if msg==ReturnQueryDataRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-00 : ReturnQueryDataRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data,self.step_data))
                    
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ReturnQueryDataRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))
                                                                                                                               
                
                ''' Diagnostic Sub Code 01 '''
                       
                if msg==RestartCommunicationsOptionRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-01 : RestartCommunicationsOptionRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = RestartCommunicationsOptionRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                    
                
                ''' Diagnostic Sub Code 02 '''  

                if msg==ReturnDiagnosticRegisterResponse:
                    lgr.info('\n \t \t \t  Fuzzing  FC 08-02 : ReturnDiagnosticRegisterRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ReturnDiagnosticRegisterRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response==""or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 03 '''
                       
                if msg==ChangeAsciiInputDelimiterRequest:
                    lgr.info('\n \t \t \t   Fuzzing  FC 08-03 : ChangeAsciiInputDelimiterRequest  .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ChangeAsciiInputDelimiterRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                   
                
                ''' Diagnostic Sub Code 04 '''
                         
                if msg==ForceListenOnlyModeRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-04 : ForceListenOnlyModeRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                  
                        handle  = ForceListenOnlyModeRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 10 '''
                         
                if msg==ClearCountersRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-10 : ClearCountersRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ClearCountersRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                             
                
                ''' Diagnostic Sub Code 11 '''
                          
                if msg==ReturnBusMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-11 : ReturnBusMessageCountRequest  .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnBusMessageCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 12 '''
                        
                if msg==ReturnBusCommunicationErrorCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-12 : ReturnBusCommunicationErrorCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                   
                        handle  = ReturnBusCommunicationErrorCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        #lgr.info('Answer >>  response %r'  % (response, ))
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                
                
                ''' Diagnostic Sub Code 13 '''
                        
                if msg==ReturnBusExceptionErrorCountRequest:
                    lgr.info('\n \t \t\t Fuzzing  FC 08-13 : ReturnBusExceptionErrorCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                        
                        handle  = ReturnBusExceptionErrorCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                            
                
                ''' Diagnostic Sub Code 14 '''
                          
                if msg==ReturnSlaveMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-14 : ReturnSlaveMessageCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                   
                        handle  = ReturnSlaveMessageCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                             
                
                ''' Diagnostic Sub Code 15 '''
                
                if msg==ReturnSlaveNoResponseCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-15 : ReturnSlaveNoResponseCountRequest ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):               
                        handle  = ReturnSlaveNoResponseCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                            
               
                ''' Diagnostic Sub Code 16 ''' 
                         
                if msg==ReturnSlaveNAKCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-16 : ReturnSlaveNAKCountRequest ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                    
                        handle  = ReturnSlaveNAKCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        #print >>sys.stderr, 'response %r' % (response,) 
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))
                                                     
                
                '''  Diagnostic Sub Code 17 ''' 
                      
                if msg==ReturnSlaveBusyCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-17 : ReturnSlaveBusyCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                        handle  = ReturnSlaveNAKCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                           

                '''  Diagnostic Sub Code 18  ''' 
                         
                if msg==ReturnSlaveBusCharacterOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-18 : ReturnSlaveBusCharacterOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnSlaveBusCharacterOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                '''  Diagnostic Sub Code 19 ''' 
                         
                if msg==ReturnIopOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-19 : ReturnIopOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnIopOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                                  
                
                '''  Diagnostic Sub Code 20  ''' 
                          
                if msg==ClearOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-20 : ClearOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ClearOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                                 
                '''
                 Diagnostic Sub Code 21                                sub function code = 0x0015
                '\x08\x00\x15\x00\x03'),                               GetClearModbusPlus//(Get Statistics)     
                '\x08\x00\x15\x00\x04'),                               GetClearModbusPlus//((Clear Statistics)) 
                '''         
                if msg==GetClearModbusPlusRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-21 : GetClearModbusPlusRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = GetClearModbusPlusRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=fuzz_session.master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))

                    break
            break                 
        fuzz_session.flag_reguest=False        
        lgr.info('Done sub_function_code and data field test')        
        sleep(0.1);return                                                           
          

    def test_DiagnosticRequests(self):
        '''
        This is the test for the pymodbus.diag_message module, for Diagnostics FC
        Testing diagnostic request messages for all sub_function_code and data field 
        send serial loop request 
        '''
        for a in itertools.count():
            
            for msg,enc in self.diagnostics:
                ''' Diagnostic Sub Code 00'''
            
                if msg==ReturnQueryDataRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-00 : ReturnQueryDataRequest  ....init')
                    handle  = ReturnQueryDataRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))  
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break               
                
                ''' Diagnostic Sub Code 01 '''
                       
                if msg==RestartCommunicationsOptionRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-01 : RestartCommunicationsOptionRequest  ....init')
                    handle  = RestartCommunicationsOptionRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                       lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                       lgr.info('Answer >>  response %r'  % (response, ))                
                    if fuzz_session.flag_reguest==False :
                        break
                 
                
                ''' Diagnostic Sub Code 02 '''  

                if msg==ReturnDiagnosticRegisterRequest:
                    lgr.info('\n \t \t \t  Fuzzing  FC 08-02 : ReturnDiagnosticRegisterRequest  ....init ')                   
                    handle  = ReturnDiagnosticRegisterRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                     
                 
                
                ''' Diagnostic Sub Code 03 '''
                       
                if msg==ChangeAsciiInputDelimiterRequest:
                    lgr.info('\n \t \t \t   Fuzzing  FC 08-03 : ChangeAsciiInputDelimiterRequest  .... init')
                    
                    handle  = ChangeAsciiInputDelimiterRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                  
                    if fuzz_session.flag_reguest==False :
                        break                
                
                ''' Diagnostic Sub Code 04 '''
                         
                if msg==ForceListenOnlyModeRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-04 : ForceListenOnlyModeRequest  ....init')                       
                    handle  = ForceListenOnlyModeRequest(a)
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result) 
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                     
                
                ''' Diagnostic Sub Code 10 '''
                         
                if msg==ClearCountersRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-10 : ClearCountersRequest  ....init')                       
                    handle = ClearCountersRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)                   
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))

                    if fuzz_session.flag_reguest==False :
                        break
                    
                
                ''' Diagnostic Sub Code 11 '''
                          
                if msg==ReturnBusMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-11 : ReturnBusMessageCountRequest  .... init ')
                    handle  = ReturnBusMessageCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or ((type(response)) is str and len(response)==1): 
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break
                    
                ''' Diagnostic Sub Code 12 '''
                        
                if msg==ReturnBusCommunicationErrorCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-12 : ReturnBusCommunicationErrorCountRequest .... init')
                    
                    handle  = ReturnBusCommunicationErrorCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
               
                    if fuzz_session.flag_reguest==False :
                        break
                    
               
                ''' Diagnostic Sub Code 13 '''
                        
                if msg==ReturnBusExceptionErrorCountRequest:
                    lgr.info('\n \t \t\t Fuzzing  FC 08-13 : ReturnBusExceptionErrorCountRequest .... init')
                       
                    handle  = ReturnBusExceptionErrorCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                          
                
                ''' Diagnostic Sub Code 14 '''
                          
                if msg==ReturnSlaveMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-14 : ReturnSlaveMessageCountRequest .... init')                                  
                    handle  = ReturnSlaveMessageCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                           
                
                """ Diagnostic Sub Code 15"""
                        
                if msg==ReturnSlaveNoResponseCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-15 : ReturnSlaveNoResponseCountRequest ....init')                    
                    handle  = ReturnSlaveNoResponseCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                         
               
                ''' Diagnostic Sub Code 16 ''' 
                         
                if msg==ReturnSlaveNAKCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-16 : ReturnSlaveNAKCountRequest ....init')
                    handle  = ReturnSlaveNAKCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                            break                     
                
                '''  Diagnostic Sub Code 17 ''' 
                      
                if msg==ReturnSlaveBusyCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-17 : ReturnSlaveBusyCountRequest .... init')                    
                    handle  = ReturnSlaveNAKCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                            break                     

                
                '''  Diagnostic Sub Code 18  ''' 
                         
                if msg==ReturnSlaveBusCharacterOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-18 : ReturnSlaveBusCharacterOverrunCountRequest .... init')
                    handle  = ReturnSlaveBusCharacterOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                    
                
                '''  Diagnostic Sub Code 19 ''' 
                         
                if msg==ReturnIopOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-19 : ReturnIopOverrunCountRequest .... ')
                    
                    handle  = ReturnIopOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                    
                
                '''  Diagnostic Sub Code 20  ''' 
                          
                if msg==ClearOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-20 : ClearOverrunCountRequest .... ')                                        
                    handle  = ClearOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                         
                '''
                 Diagnostic Sub Code 21                                sub function code = 0x0015
                '\x08\x00\x15\x00\x03'),                               GetClearModbusPlus/(Get Statistics)     
                '\x08\x00\x15\x00\x04'),                               GetClearModbusPlus/((Clear Statistics)) 
                '''         
                if msg==GetClearModbusPlusRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-21 : GetClearModbusPlusRequest .... ')
                    handle  = GetClearModbusPlusRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break
            
            if fuzz_session.flag_reguest==False :
                        break             
        fuzz_session.flag_reguest=True        
        lgr.info('Empty Diagnostic Sub Code ')
        #fuzz_session.way= 0 and fuzz_session.priority==3/test_field_PDU, all test, fuzz_session.test_format all case not  
        if fuzz_session.way==0 and fuzz_session.priority==3 :fuzz_session.flag_test_FC08_pair==True;self.test_DiagnosticRequests_data_field() #fuzz_session.way= 0, all test
        sleep(1.0);return                                                    
            
