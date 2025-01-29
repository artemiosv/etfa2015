
#!/usr/bin/env python
# -*- coding: utf-8 -*-


import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import logging.handlers as handlers
import fuzz_session
import  struct
import random
import sys,csv, math
from utils_b import *
from modbus_tk.utils import threadsafe_function, flush_socket, to_data
from defines import *
#from utils_b import is_way,not_exist_field
#from raise_except import (CsvError,TestfieldError) #exception for raise_except

from scapy.all import *
from add_method  import ByteToHex,rand_XShortField,random_bit,random_id,rand_binary,rand_ShortEnumField,randstring,fib2, rand_XByteField,rand_ByteEnumField, rand_FieldLenField,rand_ByteField,rand_IntEnumField,rand_StrLenField

#add v1.1
import basetest
from basetest.fuzz_patterns import * # Library for fuzzing message >>> Filename: fuzz_patterns.py

logger = modbus_tk.utils.create_logger("console") # create logger- 
lgr=logging.getLogger('')


class fuzzer_payload ():
    
    def __init__(self):
      """
      """
      #Looking for send some pdu request bad,response,and exception and diagnostics
      #Library for fuzzing message >>> Filename: fuzz_patterns.py
              
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


    
    def fuzz_payload(self,pdu):
       """
       This functions fuzzes a payload
       def ne in start = [ 'repeat','remove','random_pdu','message']
       l.insert(newindex, l.pop(oldindex)) first element go to end
       """
       fuzz_type = fuzz_session.fp[0]       
       fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0)) 
       lgr.warn('Fuzzing a payload: ' + fuzz_type)            
       adu,pdu=self.fuzz_payload_func[fuzz_type](pdu)   
       return adu,pdu
    
    def payload_remove(pdu):
       """
       This function removes a payload pdu from the packet
       """

       adu = ""
       lgr.warn('Fuzzing a remove field pdu')
       payloads_pdu = []  
       cur_payload = pdu    
       new_pdu=to_data('')
       pdu=new_pdu
       return adu,pdu

    def payload_random_pdu(pdu): 
       '''
       This function inserts a random pdu payload in the packet
       define, choice  global/payload_pdu=['diagnostics','randByte','randBit',zerobyte',corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception']      
       fuzzer_ADU().Invalidlen(pdu) , smart value for len
       l.insert(newindex, l.pop(oldindex)) first element go to end
       ''' 
       global flag_pdu 
       fMbap=basetest.fuzzer_ADU() #ver 1.1. set 
       
       length=0 ; item=0  ; adu = ""   
               
       fuzz_random = fuzz_session.payload_pdu[0]       
       fuzz_session.payload_pdu.insert(len(fuzz_session.payload_pdu)+1,fuzz_session.payload_pdu.pop(0)) 
       lgr.warn('insert random  PDU: %r ' %fuzz_random)             
       
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
                  lgr.info('Random sendbad as PDU: %r' % ByteToHex(pdu))
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
                   lgr.info('Random sendbad after PDU: %r' % ByteToHex(pdu))
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
                  lgr.info('Random sendresponse as PDU: %r' % ByteToHex(pdu))
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
                   lgr.info('Random  sendresponse after PDU: %r' % ByteToHex(pdu))
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
                  lgr.info('Random exception as PDU: %r' % ByteToHex(pdu))
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
                   lgr.info('Random exception after PDU: %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                               
       elif fuzz_random  =='diagnostics' :
          if flag_pdu==0 :
            i=random.randint(1,19)
            item=i                                                                  #item in  pdu                                  
            for fct,msg  in basetest.diagnostics:
                item -= 1
                if  item == 0 :
                  fc,sub=struct.unpack(">BH", msg[0:3].encode())
                  data=rand_XShortField()                                
                  pdu=struct.pack(">BHH",fc,sub,data)                              #fc +sub +random data (0 -ffff)
                  flag_pdu=1
                  lgr.info('Random  diagnostics as PDU: %r' % ByteToHex(pdu))
                  return adu,pdu
                else :
                  continue                 
          else :                                                                   #flag_pdu==1
            item=random.randrange(1,19)                                            #flag pdu=1 send pdu+++...                        
            for fct,msg  in basetest.diagnostics:                                  
                pdu +=bytearray([ ord(p) for p in msg]) 
                item -= 1                
                if item==0 :
                   flag_pdu=0
                   lgr.info('Random  diagnostics after PDU: %r' % ByteToHex(pdu))
                   return adu,pdu
                else :
                   continue
                             
       elif  fuzz_random =='randByte' :
         #n_byte_len=fuzzer_ADU().Invalidlen(pdu)
         n_byte_len=fMbap.Invalidlen(pdu) 
         pdu='\x00\x00\xff\xff'+''.join(chr(random.randint(0,255)) for _ in range(n_byte_len)) + '\xff\xff'       #+2 byte +  random char +2 byte  
         lgr.info('Random  byte PDU first 20 ByteHex: %r' % ByteToHex(bytearray([ ord(p) for p in pdu[:20]])))
         return adu,bytearray([ ord(p) for p in pdu])                                      
  
       elif fuzz_random  =='randBit' : 
           n_byte_len=fMbap.Invalidlen(pdu)                                                                                 
           pdu= '\x00\x00\xff\xff'+ ''.join(random_bit(n_byte_len))+'\xff\xff'          
           lgr.info(('Random_bit %d n_ranbit' % (n_byte_len)))           
           lgr.info('Random bit PDU first 20 ByteHex: %r' % ByteToHex(bytearray([ ord(p) for p in pdu[:20]])))       
           return adu,bytearray([ ord(p) for p in pdu]) 

       elif fuzz_random  =='zerobyte' :
           n_byte_len=fMbap.Invalidlen(pdu) 
           lgr.info(('zerobyte %d n_zero_len' % (n_byte_len)))           
           lgr.info('Zero PDU, first 20 ByteHex: %r' % ByteToHex(b"".join(struct.pack('B', random.randint(0, 0)) for _ in range(n_byte_len)[:20])))          
           return adu,b"".join(struct.pack('B', random.randint(0, 0)) for _ in range(n_byte_len))                            
       
       elif fuzz_random  =='corrupt_bytes' :
           length=len(pdu)
           n=random.randint(1,length)
           pdu=scapy.utils.corrupt_bytes(pdu, p=0.02, n=2)                                                  #corrupt_bytes random 1-len(pdu)                       
           lgr.info('Corrupt_bytes PDU: %r' % ByteToHex(pdu))                     
       
       elif fuzz_random  =='corrupt_bits' :
           length=len(pdu)
           n=random.randint(1,length)
           pdu=scapy.utils.corrupt_bits(pdu, p=0.02, n=2)                                                    #scapy library,flip a given percentage or number of bits from a string                                                                    
           lgr.info('Corrupt_bits PDU: %r' % ByteToHex(pdu))            

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

    def payload_message(pdu):
        '''
        This function inserts a raw data after TCP as valid the packet Modbus/TCP
        Generation inputs of Death 
        '''

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

