
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
from random import *

from scapy.all import *
from add_method  import ByteToHex,rand_XShortField,random_bit,random_id,rand_binary,rand_ShortEnumField,randstring,fib2, rand_XByteField,rand_ByteEnumField, rand_FieldLenField,rand_ByteField,rand_IntEnumField,rand_StrLenField

#add v1.1
import basetest
from basetest.fuzz_patterns import * # Library for fuzzing message >>> Filename: fuzz_patterns.py
#from  basetest.s_primitives import *

logger = modbus_tk.utils.create_logger("console") # create logger- 
lgr=logging.getLogger('')


#This functions fuzzes a field of pdu  (** look spec Modbus)
class fuzzer_pdu():
        
    
    def __init__(self ):
        """Constructor. Set the communication settings"""        
        fMbap=basetest.fuzzer_ADU() #ver 1.1. set 

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
           
            lgr.info('record_length: %r' % (record.record_length+1))                                           
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
        self.record_number   = 0x00
        self.record_data     = ''

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
            lgr.info('record_data: %r' % ByteToHex(packet))   
                       
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
    # This function  send invalid FC in pdu
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
        """
        invalid address return out upper last_address/first address ...
        Define global, Common_add_fuz=[0,1,2,3,.32768.,65535,65534,65533] list of common fuzzing address
        """ 
        #import fuzz_session      
        if function_code == READ_COILS or function_code== WRITE_SINGLE_COIL or function_code == WRITE_MULTIPLE_COILS : 
            #select first item and rotate
            fuz_add = fuzz_session.fuzz_addre_COILS[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0            
            fuzz_session.fuzz_addre_COILS.insert(len(fuzz_session.fuzz_addre_COILS)+1,fuzz_session.fuzz_addre_COILS.pop(0))               #l.insert(newindex, l.pop(oldindex))
            
            if fuz_add  <fuzz_session.MIN_COILS or fuz_add >fuzz_session.MAX_COILS:  
                lgr.warn('address invalid: %d, 0x%02X' % (fuz_add,fuz_add))
            else :
                lgr.info('address valid: %d, 0x%02X' % (fuz_add,fuz_add))
           
            return fuz_add 
        
        elif function_code == READ_DISCRETE_INPUTS :            
            fuz_add =fuzz_session.fuzz_addre_DIS_IN[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0
            
            if fuz_add  <fuzz_session.MIN_DIS_IN or fuz_add >fuzz_session.MAX_DIS_IN:  
                lgr.warn('address invalid: %d, 0x%02X ' % (fuz_add,fuz_add))
            else :
                lgr.info('address valid: %d, 0x%02X' % (fuz_add,fuz_add))

            return fuz_add 
            
            fuzz_session.fuzz_addre_DIS_IN.insert(len(fuzz_session.fuzz_addre_DIS_IN)+1,fuzz_session.fuzz_addre_DIS_IN.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add 

        elif function_code == READ_INPUT_REGISTERS :          
            fuz_add =fuzz_session.fuzz_addre_IN_REG[0]           
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0

            
            if fuz_add  <fuzz_session.MIN_IN_REG or fuz_add >fuzz_session.MAX_IN_REG:  
                lgr.warn('address invalid: %d, 0x%02X' % (fuz_add,fuz_add))
            else :
                lgr.info('address valid: %d, 0x%02X' % (fuz_add,fuz_add))

            fuzz_session.fuzz_addre_IN_REG.insert(len(fuzz_session.fuzz_addre_IN_REG)+1,fuzz_session.fuzz_addre_IN_REG.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add     
        
        elif function_code == READ_HOLDING_REGISTERS or function_code == WRITE_MULTIPLE_REGISTERS or function_code ==Read_Write_Multiple_Registers or function_code ==Mask_Write_Register  :           
            fuz_add =fuzz_session.fuzz_addre_HO_REG[0] 
            if  fuz_add > 65535 or fuz_add <0:
                fuz_add=0
            
            if fuz_add  <fuzz_session.MIN_HO_REG or fuz_add >fuzz_session.MAX_HO_REG:  
                lgr.warn('address invalid: %d, 0x%02X' % (fuz_add,fuz_add))
            else :
                lgr.info('address valid: %d, 0x%02X' % (fuz_add,fuz_add))

            fuzz_session.fuzz_addre_HO_REG.insert(len(fuzz_session.fuzz_addre_HO_REG)+1,fuzz_session.fuzz_addre_HO_REG.pop(0))               #l.insert(newindex, l.pop(oldindex))
            return fuz_add 
        
        else :
            return 0
                         
    def Invalid_rec_len(self):                                                  
        """
        FC 20,21 function  invalid quantity len data 
        invalid quantity is passed    
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

    def Invalid_quantity(self,function_code):
        """
        This function  invalid quantity in PDU
        invalid quantity is nearest limit ,smart value..
        """        
        
        # Quantity of Registers  2 Bytes   1 to 125 (0x7D)
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) :                                                              
            random_quantity=fuzz_session.qua_IN_REG_HO_REG[0]
            
            if random_quantity>125 or random_quantity==0:                                               
                lgr.warn('quantity invalid: %d, 0x%02X' % (random_quantity,random_quantity))
            else :
                lgr.info('quantity valid: %d, 0x%02X' % (random_quantity,random_quantity))                                             
            fuzz_session.qua_IN_REG_HO_REG.insert(len(fuzz_session.qua_IN_REG_HO_REG)+1,fuzz_session.qua_IN_REG_HO_REG.pop(0))
            return random_quantity
        
        elif (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
            # Quantity of Registers  2 Bytes   1 to 2000 (0x7D)                
            random_quantity= fuzz_session.qua_COILS_DIS_IN[0]
            
            if random_quantity>2000 or random_quantity==0:                                                
                lgr.warn('quantity invalid: %d,0x%02X' % (random_quantity,random_quantity))
            else :
                lgr.info('quantity valid: %d, 0x%02X' % (random_quantity,random_quantity))  
            fuzz_session.qua_COILS_DIS_IN.insert(len(fuzz_session.qua_COILS_DIS_IN)+1,fuzz_session.qua_COILS_DIS_IN.pop(0))                  
            return random_quantity 

        #16 (0x10) write a block of contiguous registers (1 to  123  registers)
        #23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write =121        
        elif function_code == WRITE_MULTIPLE_REGISTERS  or function_code == Read_Write_Multiple_Registers:
            random_quantity= fuzz_session.qua_WR_MU_REG_RW_Multiple[0]
            
            if random_quantity>125 or random_quantity==0:     #                                          
                lgr.warn('quantity invalid: %d, 0x%02X' % (random_quantity,random_quantity))
            else :
                lgr.info('quantity valid: %d, 0x%02X' % (random_quantity,random_quantity))  
            fuzz_session.qua_WR_MU_REG_RW_Multiple.insert(len(fuzz_session.qua_WR_MU_REG_RW_Multiple)+1,fuzz_session.qua_WR_MU_REG_RW_Multiple.pop(0))                 
            #fuzz_session.qua_IN_REG_HO_REG.insert(len(fuzz_session.qua_IN_REG_HO_REG)+1,fuzz_session.qua_IN_REG_HO_REG.pop(0))
            return random_quantity             
           
        elif function_code == WRITE_MULTIPLE_COILS : 
            # Quantity of Registers  2 Bytes   1 to 1968
            random_quantity= fuzz_session.qua_W_MUL_COILS [0]
            if random_quantity>1968 or random_quantity==0:                                               
                lgr.warn('quantity invalid: %d, 0x%02X' % (random_quantity,random_quantity))
            else :
                lgr.info('quantity valid: %d, 0x%02X' % (random_quantity,random_quantity))  
            fuzz_session.qua_W_MUL_COILS.insert(len(fuzz_session.qua_W_MUL_COILS)+1,fuzz_session.qua_W_MUL_COILS.pop(0))
            return random_quantity                  
          
        else :
            pass    
        return  1       
         
    def Invalid_output_value(self) :
        """       
        This function  invalid output_value in PDU in WRITE_SINGLE_COIL, WRITE_SINGLE_REGISTER
        random in (0,65534)
        """  
        while 1 :
          n=random.randint(0,65534)        
           
          if 'n' not in fuzz_session.foo_value: 
            fuzz_session.foo_value.append(n)
            return n 
          else :                                                           
            random_value = random.choice(fuzz_session.foo_value)
            return random_value  

    def fuzz_field_pdu(self,pdu):        
        """
        The functions below fuzz field PDU Modbus
        f_reg=['function_code', 'starting_address', 'quantity_of_x']
        f_wr=['function_code', 'starting_address', 'output_value']
        f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
        f_read_file_rec=['function_code', 'Byte_Count','Reference_Type','File number','Record number','Record length']
        f_write_file_rec=['Data_length','Reference_Type','File number','Record number','Record_length',Record data']
        f_mask=['function_code', 'and_mask','or_mask']
        f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']
        f_test_FC43=['function_code','mei_type','read_code','object_id' ]  
        """
        
        global nu_reg
        
        fMbap=basetest.fuzzer_ADU() 

        if fuzz_session.fuzz_two_fields==True :                                      
            #adu=fuzzer_ADU().fuzz_field_mbap(pdu,slave)
            adu=fMbap.fuzz_field_mbap(pdu,slave) 
            fuzz_session.fuzz_two_fields==False
        else :
           adu=""
        #extract function_code       
        (function_code,)= struct.unpack(">B", pdu[0:1])                                      
       
        lgr.info('Fuzzing FC: %d, 0x%02X'  % (function_code,function_code))                  
        
        if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):            
              (starting_address, quantity_of_x) = struct.unpack(">HH", pdu[1:5])                            
              field = fuzz_session.f_reg[0]
              #l.insert(newindex, l.pop(oldindex))
              fuzz_session.f_reg.insert(len(fuzz_session.f_reg)+1,fuzz_session.f_reg.pop(0))                                
              lgr.info('Fuzzing field PDU: %s' % field)#.rstrip('\n') #;lgr.info(message.rstrip('\n')) 
              #line.strip()
              
              if field == 'function_code':
                    function_code = self.Invalidfnc()                                          
                    pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                    lgr.warn('FC: %d, 0x%02X' % (function_code,function_code))
              elif field == 'starting_address':                     
                    starting_address=self.Invalidaddress(function_code)                       
                    pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
              elif field == 'quantity_of_x':                    
                    quantity_of_x=self.Invalid_quantity(function_code)                                                          
                    pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
              else :
                    lgr.warn('not fuzzing') #case not exist field  of test 
              
              fuzz_session.starting_address=starting_address   
              return adu,pdu            

        if function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
              starting_address,output_value = struct.unpack(">HH", pdu[1:5])
              field = fuzz_session.f_wr[0]
              #l.insert(newindex, l.pop(oldindex))
              fuzz_session.f_wr.insert(len(fuzz_session.f_wr)+1,fuzz_session.f_wr.pop(0))                                               
              lgr.info('Fuzzing field PDU: %s '% field )

              if field == 'function_code':
                       function_code = self.Invalidfnc()      
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.warn(': %d, 0x%02X' % (function_code,function_code))                       
              elif field == 'starting_address' :              
                       starting_address=self.Invalidaddress(function_code)
                       pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                       lgr.warn(': %d, 0x%02X' % (starting_address,starting_address))                       
              elif field == 'output_value' :              
                       output_value=self.Invalid_output_value()                      
                       pdu = struct.pack(">BH", function_code, starting_address)
                       pdu+= struct.pack("<H", output_value)                       
                       lgr.warn(': %d, 0x%02X ' % (output_value, output_value))
              else :
                       lgr.warn('not fuzzing')
                       
              return  adu,pdu              

        if function_code == WRITE_MULTIPLE_REGISTERS or function_code == WRITE_MULTIPLE_COILS :
              """execute modbus function 15/16
              get the starting address and the number of items from the request pdu
              byte_value= random.choice(list_of_coils)
              randBitList = lambda n: [randint(0,1) for b in range(1,n+1)]
              output_value= random.choice(list_of_regs) 
              """               
              starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
              output_value=pdu[7:]                                                     #register value or coil value first message             
              field = fuzz_session.f_mul_coil_reg[0]
              fuzz_session.f_mul_coil_reg.insert(len(fuzz_session.f_mul_coil_reg)+1,fuzz_session.f_mul_coil_reg.pop(0))                                                                 
              list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*200, list(range(999)), (27, ), (1, 2, 3, 4), list(range(4500)),list(range(1999)),list(range(2999))]                                   #add more elemennts                                 
              list_of_coils = [ (1, 0, 1, 1)*2222, (0, )*3333, (1, )*2323, [0, 1]*2199, [1]*12118, [1, 1]*2256, [1, 0, 1 ,1 , 1 ,1 ,1 ]*700, (1, 0, 0, 1), [1, 0]*11110]                         
              randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List
              lgr.info('Fuzzing field PDU: %r' % field )                                                                
              
              if  field== 'function_code' :
                  function_code = self.Invalidfnc()                            
                  lgr.info(': %d, 0x%02X' % (function_code,function_code))                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                                                            
                  pdu += output_value                                   

              elif field == 'starting_address':   
                  starting_address=self.Invalidaddress(function_code)                 
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)
                  lgr.info(': %d, 0x%02X' % (starting_address,starting_address))                 
                  pdu += output_value

              elif field == 'quantity_of_x':  
                #  quantity_of_x  - max size 123 register in one read, max allow coils 1968
                  if function_code==WRITE_MULTIPLE_REGISTERS  :             
                        quantity_of_x=self.Invalid_quantity(function_code)
                        lgr.info(': %d, 0x%02X' % (quantity_of_x,quantity_of_x ))                       
                  else :                                         
                        quantity_of_x= self.Invalid_quantity(function_code)
                        lgr.info(': %d, 0x%02X' % (quantity_of_x,quantity_of_x )) 
                        
                  pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x, byte_count)                  
                  pdu += output_value                                                 

              elif field == 'byte_count':                                                                    # number data bytes to follow len(output_value) / 8  ,2 * len(output_value)                  
                    byte_count= rand_XByteField()                                               
                    lgr.info(': %d, 0x%02X' % (byte_count,byte_count))
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
            lgr.info('Fuzzing field PDU:'+ field )
                            
            if  field== 'function_code' :
                function_code = self.Invalidfnc()                                                                                                                                                                          
                lgr.info(': %d, 0x%02X' % (function_code,function_code))                
                                                                                                                      
            elif field== 'Byte_Count' : 
                Byte_Count= self.Invalid_rec_len()                                   #normal x07 to 0xF5 /7-245 one Byte
                lgr.info(': %d, 0x%02X' % (Byte_Count,Byte_Count))
                
            elif field== 'Reference_Type' :                                          #for first group choise Reference_Type                      
                Reference_Type=self.Invalid_RType()                                  #boundary rangs 0,1,2,3,4,5,7,9,10
                lgr.info(': %d, 0x%02X' % (Reference_Type,Reference_Type))
                                
            elif field=='File_number' :
                 File_number= fuzz_session.value_test_file_number[0]                                                      
                 #l.insert(newindex, l.pop(oldindex))
                 fuzz_session.value_test_file_number.insert(len(fuzz_session.value_test_file_number)+1,fuzz_session.value_test_file_number.pop(0))                
                 lgr.info(': %d, 0x%02X' % (File_number,File_number))

            #starting address, addressed as 0000-270F hexadecimal (0000-9999 decimal).  
            elif field== 'Record_number' : 
                 Record_number=fuzz_session.value_test_record_number[0]
                 fuzz_session.value_test_record_number.insert(len(fuzz_session.value_test_record_number)+1,fuzz_session.value_test_record_number.pop(0)) 
                 lgr.info(': %d, 0x%02X' % (Record_number,Record_number))
                
            #record_length=max N=122X2 byte 244byte max, for valid len frame 
            elif field== 'Record_length' :
                 Record_length=fuzz_session.value_test_record_length[0]
                 fuzz_session.value_test_record_length.insert(len(fuzz_session.value_test_record_length)+1,fuzz_session.value_test_record_length.pop(0))  
                 lgr.info(': %d, 0x%02X' % (Record_length,Record_length))
                           
            else :
                lgr.warn('not fuzzing')
            
            fuzz_session.record1='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Record_number,Record_length)      #return fuzzing record1
            pdu  = struct.pack(">BBBHHH",function_code,Byte_Count,Reference_Type,File_number,Record_number,Record_length)
            pdu += message
            return  adu,pdu 

        """ 
        Write File Record  FC 21
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
              lgr.info('Fuzzing field  PDU: '+ field )
                             
              if  field== 'function_code' :
                  function_code = self.Invalidfnc() 
                  lgr.warn(': %d, 0x%02X' % (function_code,function_code))                                                                                               
                                  
              elif field== 'Data_length' : 
                  Request_Data_length= self.Invalid_rec_len()
                  lgr.info(': %d, 0x%02X' % (Request_Data_length,Request_Data_length,))
                                  
              elif field== 'Reference_Type' :                                                             #for first group choise Reference_Type                      
                  Reference_Type=self.Invalid_RType()                                                     #boundary rangs 0,1,2,3,4,5,7,9,10
                  lgr.info(' : %d....0x%02X' % (Reference_Type,Reference_Type))

              elif field=='File_number' :
                  File_number= fuzz_session.value_test_file_number[0]                                                      
                 #l.insert(newindex, l.pop(oldindex))
                  fuzz_session.value_test_file_number.insert(len(fuzz_session.value_test_file_number)+1,fuzz_session.value_test_file_number.pop(0))                
                  lgr.info(': %d,0x%02X' % (File_number,File_number))
              
              elif field=='Record_number' :
                  Record_number=fuzz_session.value_test_record_number[0]
                  fuzz_session.value_test_record_number.insert(len(fuzz_session.value_test_record_number)+1,fuzz_session.value_test_record_number.pop(0)) 
                  lgr.info(': %d, 0x%02X' % (Record_number,Record_number))

               #record_length=max N=122X2 byte for len 260 packet   
              elif field=='Record_length' :
                  Record_length=fuzz_session.value_test_record_length[0]
                  fuzz_session.value_test_record_length.insert(len(fuzz_session.value_test_record_length)+1,fuzz_session.value_test_record_length.pop(0))  
                  lgr.info(': %d, 0x%02X' % (Record_length,Record_length))
                    
              elif field=='Record_data' :                                                                              
                   Record_data=bytearray(random.getrandbits(8) for _ in range(self.Invalid_rec_len()))                        # smart value_test_Byte_count=[0,1,2,3,4,5,6,246,247,248,249,250,251,252,253,254,255]                   
                   lgr.info('Record_length: %d..0x%02X ,len of Record_data: %d..' % (Record_length,Record_length,len(Record_data)))                 
                   lgr.info(': %r ' % (ByteToHex(Record_data)))
                                                 
              else :
                  lgr.warn('not fuzzing')                  
              
              #return fuzzing record1
              fuzz_session.record1='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Record_number,Record_length) 
              pdu  = struct.pack(">BBBHHH",function_code,Request_Data_length,Reference_Type,File_number,Record_number,Record_length)                  
              pdu += Record_data+message              
              return  adu,pdu

        """ 22 (0x16) Mask Write Register """
        if function_code == Mask_Write_Register :

            field = fuzz_session.f_mask[0]
            fuzz_session.f_mask.insert(len(fuzz_session.f_mask)+1,fuzz_session.f_mask.pop(0)) 
            lgr.info('Fuzzing field PDU: '+ field )
            starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
            if field == 'function_code':
                 function_code = self.Invalidfnc()                           
                 lgr.info(': %d, 0x%02X' % (function_code,function_code))
                 pdu = struct.pack(">BHHH", function_code,starting_address, and_mask, or_mask)
            
            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)
                 lgr.info(': %d, 0x%02X' % (starting_address,starting_address))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask )     

            elif field == 'or_mask' :             
                 or_mask= rand_XShortField()                                         #2 byte
                 lgr.info(': %r, 0x%02X' % (or_mask,or_mask))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask,)
            
            elif field == 'and_mask' :             
                 and_mask= rand_XShortField()                                        
                 lgr.info(': %r, 0x%02X' % (and_mask,and_mask,))
                 pdu = struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask)                    
                 
            else :                                                   
                 lgr.warn('not fuzzing')                                                              
      
            return  adu,pdu 

        """24 (0x18) Read FIFO Queue"""
        if function_code == Read_FIFO_queue :
             
            field = random.choice (['function_code', 'starting_address'])          
            lgr.info('Fuzzing field PDU:  '+ field )
            starting_address,=struct.unpack(">H", pdu[1:])                  
                      
            if field == 'function_code':
                 function_code = self.Invalidfnc()                           
                 pdu = struct.pack(">BH", function_code, starting_address)
                 lgr.info(': %d, 0x%02X' % (function_code,function_code))

            elif field == 'starting_address' :             
                 starting_address=self.Invalidaddress(function_code)                 
                 pdu = struct.pack(">BH",function_code ,starting_address)
                 lgr.info(': %d' % starting_address)
            else :                                                   
                 lgr.warn('not fuzzing') 
            return  adu,pdu     

        """ 23 /( 0x17) Read_Write_Multiple_Registers """
        if function_code == Read_Write_Multiple_Registers  :
        
            field =fuzz_session.f_rw_reg[0]
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.f_rw_reg.insert(len(fuzz_session.f_rw_reg)+1,fuzz_session.f_rw_reg.pop(0))
            lgr.info('Fuzzing field PDU: ' + field )

            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List 
            list_of_regs = [(20, 2, 19, 75, 42), (15, ), [11, 12]*20, list(range(999)), (27, ), (1, 2, 3, 4), list(range(4500)),list(range(1100)),list(range(500))]           
            #Decode request for fuzz
            read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
            message=pdu[11:]
                        
            if field == 'function_code':
                 function_code = self.Invalidfnc()
                 lgr.info(': %d, 0x%02X' % (function_code,function_code))                                                          
                 
            elif field == 'read_address':                     
                 read_address=self.Invalidaddress(function_code)                                        
                 lgr.info(': %d, 0x%02X' % (read_address,read_address))  
            
            elif field == 'write_address':                     
                 read_address=self.Invalidaddress(function_code)                                        
                 lgr.info(': %d, 0x%02X' % (write_address,write_address))  

            elif field == 'read_count' :                                                           # Quantity to Read/2 byte/ 1-125
                 read_count=self.Invalid_quantity(function_code)             
                 lgr.info(': %d' % read_count)
                            
            elif field == 'write_count' :                                                          #Quantity to Write/2 byte /1-127       
                 write_count=self.Invalid_quantity(function_code)
                 lgr.info(': %d' % write_count)
                                              
            elif field == 'write_byte_count' :                                                     # Write byte count/1 byte /2*N (Quantity to Write)                                                      
                 write_byte_count=fuzz_session.value_w_byte_count[0]  #from dict_operation  --replace with interesting value /lib_interesting_256 
                 lgr.info(': %d' % write_byte_count)
                 fuzz_session.value_w_byte_count.insert(len(fuzz_session.value_w_byte_count)+1,fuzz_session.value_w_byte_count.pop(0))
                             
            elif field == 'value':                                                                  # Quantity  to Write  1-121
                 pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count)                          
                 output_value=bytearray(random.getrandbits(8) for _ in range(fuzz_session.value_w_fc23[0]))                                                                                                                                                              
                 lgr.info('Register value: %d' % (len(output_value)//2))
                 lgr.info(': %r' % (ByteToHex(output_value)))                                   
                 fuzz_session.value_w_fc23.insert(len(fuzz_session.value_w_fc23)+1,fuzz_session.value_w_fc23.pop(0))
                 return  adu,pdu+output_value
            else :                                                   
                 lgr.warn('not fuzzing')                                                             
 
            pdu= struct.pack(">BHHHHB",function_code,read_address, read_count, write_address, write_count,write_byte_count )
            pdu += message           
            return  adu,pdu  

        """Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
        f_test_FC43=['function_code','mei_type','read_code','object_id' ] 
        function_code = 0x2b, sub_function_code = 0x0e
        Read Device ID code                      Object Name
        DeviceInformation_Basic:  0x01,         range [0x00 -0x02]    
        DeviceInformation_Regular= 0x02 ,       range [0x03 -0x7F]
        DeviceInformation_Extended= 0x03 ,      range [0x80–0xFF] 
        DeviceInformation_Specific= 0x04 , 
        dict_operation_,
        """

        if function_code == Read_device_Identification :
        
            mei_type,read_code,object_id = struct.unpack(">BBB", pdu[1:5])

            field = fuzz_session.f_test_FC43[0]              
            fuzz_session.f_test_FC43.insert(len(fuzz_session.f_test_FC43)+1,fuzz_session.f_test_FC43.pop(0)) 
            lgr.info('Fuzzing field PDU: '+ field )        
            
            if field == 'function_code':
                function_code = self.Invalidfnc()
                lgr.warn(': %d, 0x%02X' % (function_code,function_code))   

            elif field=='mei_type' :                                                     
                mei_type=rand_XByteField() 

            elif field=='read_code' :
                read_code=rand_XByteField()
                
            elif field=='object_id' :
                object_id =rand_XByteField()#random.randint(0,255) in add_method.py
                      
            else :
                lgr.warn('not fuzzing')   # case not exist field  of test

            #Check  mei_type, read_code, object_id specification valid   
            if mei_type !=14:
               
               lgr.warn('mei_type invalid: %d, 0x%02X' % (mei_type,mei_type))
                           
            else :
                lgr.info('mei_type valid:  %d, 0x%02X' % (mei_type, mei_type))

            if read_code>4 or read_code==0:            
                lgr.warn('read_code invalid: % d, 0x%02X' % (read_code,read_code))       
            else :
                lgr.info('read_code valid: %d, 0x%02X' % (read_code,read_code))

            #check, read_code combinate object_id invalid
            if read_code==1 and object_id >2 :
                lgr.warn('DeviceInformation_Basic: 0x01, Object id [0x00 -0x02] '); lgr.warn('object_id invalid: %d, 0x%02X' % (object_id,object_id))
                
                        
            elif read_code==2 and  (object_id <3 or object_id>127):
                lgr.warn('DeviceInformation_Regular= 0x02, Object id [0x03 -0x7F] ');lgr.warn('object_id invalid: %d, 0x%02X' % (object_id,object_id))
                
                       
            elif read_code==3 and object_id<128:
                lgr.warn('DeviceInformation_Extended= 0x03, Object id  [0x80–0xFF]')
                lgr.warn('object_id invalid: %d, 0x%02X' % (object_id,object_id))
                        
            else: 
                lgr.info('valid object_id: %d, 0x%02X' % (object_id,object_id))

            fuzz_session.mei_type=mei_type
            fuzz_session.read_code=read_code
            fuzz_session.object_id=object_id
            return  adu,struct.pack(">BBBB", function_code,mei_type,read_code,object_id)                             
