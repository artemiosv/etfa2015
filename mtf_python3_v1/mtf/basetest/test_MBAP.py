
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import logging.handlers as handlers
import fuzz_session
import  struct
from utils_b import *
from defines import *
#from utils_b import is_way,not_exist_field
#from raise_except import (CsvError,TestfieldError) #exception for raise_except
import random
from add_method  import ByteToHex,rand_XShortField,random_bit,random_id,rand_binary,rand_ShortEnumField,randstring,fib2, rand_XByteField,rand_ByteEnumField, rand_FieldLenField,rand_ByteField,rand_IntEnumField,rand_StrLenField

logger = modbus_tk.utils.create_logger("console") # create logger- 
lgr=logging.getLogger('')

#------------------------------------------------------------------------------------------------------#
#This class fuzz testing  a field of mbap Modbus protocol
#Modbus application protocol (MBAP) in addition to the Modbus application PDU used in the serial protocol
#The MBAP header has four fields: (i) transaction identifier, (ii) protocol identifier, (iii) length, 
#and (iv) unit identifier. The transaction identifier permits devices to pair matching requests
#and replies on a communication channel.
# [         MBAP Header         ]      [ Function Code] [ Data ]
# [ tid ][ pid ][ length ][ uid ]
#    2b     2b     2b        1b           1b             Nb
#-------------------------------------------------------------------------------------------------------#


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
        fuzz_session.foo_len= [0,1,2,3,4,5,6,7,8, ..255,256 ,257,258,259,260,261,262,263,264,.. ],interesting value
        """                                                   
        random_len = fuzz_session.foo_len[0]  #in 
        fuzz_session.foo_len.insert(len(fuzz_session.foo_len)+1,fuzz_session.foo_len.pop(0))
        return random_len       

    #------------------------------------------------------------
    # This function set slave invalid in the mbap 
    # generates random, keeps history
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
       #l.insert(newindex, l.pop(oldindex)), first element go to end
       #'f_mbap':['len' ,'clone','transId', 'protoId', 'unitId' ], look serial operation
       fuzz_session.f_mbap.insert(len(fuzz_session.f_mbap)+1,fuzz_session.f_mbap.pop(0))                                                               
       lgr.info('Fuzzing field MBAP: %r' %field)
      
       if field == 'transId':   
          mbap.transaction_id= fuzzer_ADU().TransIdIs()                             
          mbap.protocol_id = 0
          mbap.length =  len(pdu)+1
          mbap.unit_id = slave                                                    
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
          lgr.warn('transId: %d, 0x%02X' % (mbap.transaction_id,mbap.transaction_id))     

       elif field == 'unitId':       
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0 
          mbap.length =  len(pdu)+1
          mbap.unit_id  = fuzzer_ADU().InvalidSlave()                             
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )  # edit only field fuzz , struct i format (4byte) 
          lgr.warn('UnitId: %d, 0x%02X' % (mbap.unit_id,mbap.unit_id))
                      

       elif field == 'len':
          mbap.transaction_id=query.get_transaction_id_b()
          mbap.protocol_id = 0                                                #is 0 for modbus spec
          mbap.length = fuzzer_ADU().Invalidlen(self)                         #fuzzing,mbap.length 
          mbap.unit_id  = slave
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id ) # edit only field fuzz , struct i format (4byte)
          mbap.len_valid =  len(pdu)+1
          if mbap.len_valid !=mbap.length: 
          		lgr.warn('Len not consist: %d, 0x%02X' % (mbap.length,mbap.length ))
          else :lgr.info('Len consist: %d, 0x%02X' % (mbap.length,mbap.length ))		

                                         
       elif field == 'protoId': 
          mbap.transaction_id=query.get_transaction_id_b()                  
          mbap.protocol_id = rand_XShortField()                               #random (0,65535)
          mbap.length = len(pdu)+1 
          mbap.unit_id  = slave 
          lgr.warn('protoId: %d, 0x%02X' % (mbap.protocol_id,mbap.protocol_id))  
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
           
       elif field == 'clone': 
          mbap=self.mbap_custom()                                             
          adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )          
          lgr.info('Clone: %d,%d,%d,%d' % (mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id))                               
          
       else:
          pass;lgr.warn('Pass error')
          
       lgr.warn('MBAP: %r ' % ByteToHex(adu))
       return adu
