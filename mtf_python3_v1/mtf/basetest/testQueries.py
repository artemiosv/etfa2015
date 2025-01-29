#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback,itertools,struct,random,logging
import logging.handlers as handlers
import fuzz_session
from add_method  import *
from random import randint
from defines import *
from time import * 
from message import *

lgr=logging.getLogger('') # create logger-

 #Read  use function of modbus_tk, script modbus.py, def execute ( ......) , execute_f is similar in modbus_b.py my script
class TestQueries():
    global search_mode, fuzz_mode, MIN_COILS, MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG
    
    def __init__(self,address_COILS=500,COILS_quantity=1,address_DIS_IN=500,DIS_IN_quantity=1,address_HO_REG=500,HO_REG_quantity=1, address_IN_REG=500,IN_REG_quantity=1,output_value=1):

        self.address_COILS = address_COILS
        self.COILS_quantity = COILS_quantity
        self.address_DIS_IN = address_DIS_IN
        self.DIS_IN_quantity = DIS_IN_quantity
        self.address_HO_REG = address_HO_REG 
        self.HO_REG_quantity = HO_REG_quantity
        self.Write_HO_REG_quantity= HO_REG_quantity
        self.address_IN_REG=address_IN_REG
        self.IN_REG_quantity = IN_REG_quantity
        self.output_value=1
        self.read_code =0x01    
        self.object_id =0x01 

    def test_ReadAnalogInputs(self):            
            """Test that response for read analog inputs (READ_INPUT_REGISTERS)
               quantity_of_x=value_range, value_range=1-125 
            """
            for a in itertools.count(): 
                    if (fuzz_session.MAX_IN_REG-fuzz_session.MIN_IN_REG) <=5: address_fuz=fuzz_session.MIN_IN_REG
                    else:address_fuz=random.randint(fuzz_session.MIN_IN_REG,(fuzz_session.MAX_IN_REG-(self.IN_REG_quantity*2)))
                    fuzz_session.master1.execute_f(slave,READ_INPUT_REGISTERS , address_fuz , self.IN_REG_quantity)
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 
                                                   
    def test_ReadDiscreteInputs(self):
            """Test that response for read digital inputs function """                                     
            for a in itertools.count():
                    if (fuzz_session.MAX_DIS_IN-fuzz_session.MIN_DIS_IN) <=5: address_fuz=fuzz_session.MIN_DIS_IN
                    else:address_fuz= random.randint(fuzz_session.MIN_DIS_IN,(fuzz_session.MAX_DIS_IN-(self.DIS_IN_quantity*2)))
                    fuzz_session.master1.execute_f(slave,READ_DISCRETE_INPUTS , address_fuz ,self.DIS_IN_quantity )
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True          
                    
    def test_WriteMultipleHr(self):
            """Check that write WRITE_MULTIPLE_REGISTERS  queries are handled correctly/contiguous registers (1 to  123  registers                     
            values_write_hr=range(123)    1,2,3,4,...120
            (MAX_HO_REG-(self.HO_REG_quantity*2)), address_fuz+self.HO_REG_quantity*2 <MAX_HO_REG
            """
            randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]                         
            for a in itertools.count():
                    if (fuzz_session.MAX_HO_REG-fuzz_session.MIN_HO_REG) <=5: address_fuz=fuzz_session.MIN_HO_REG
                    else:address_fuz= random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG-(self.HO_REG_quantity)*2)

                    fuzz_session.master1.execute_f(slave, WRITE_MULTIPLE_REGISTERS  , address_fuz , output_value=randByteList(self.HO_REG_quantity))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 

    def test_WriteMultipleCoils(self):
            """Check that write WRITE_MULTIPLE_COILS queries are handled correctly/ max 1968 value_out
            value_out tuple
            output_value=([1]*16), [1]*16,(1, ),[0, 0, 1, 1]*8,(11,12), [0]*20,[0, 1, 0, 1]*20)
            output_value=tuple([1]*1968)
            """
            randBinList = lambda n: [randint(0,1) for b in range(1,n+1)]
                                                      
            for a in itertools.count():
                    if (fuzz_session.MAX_COILS-fuzz_session.MIN_COILS) <=5: fuzz_session.address_fuz=MIN_COILS 
                    else:address_fuz= random.randint(fuzz_session.MIN_COILS,(fuzz_session.MAX_COILS-(self.COILS_quantity*2)))

                    fuzz_session.master1.execute_f(slave, WRITE_MULTIPLE_COILS , address_fuz , output_value=randBinList(self.COILS_quantity))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 

    def test_writesingleHr(self):
            """Check that write HOLDING_REGISTERS queries are handled correctly"""           
            for a in itertools.count():  
                    address_fuz= random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG)                                           
                    fuzz_session.master1.execute_f(slave, WRITE_SINGLE_REGISTER , address_fuz , output_value=random.randint(0,65535))

                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 

    def test_writecoil(self):
            """Check that write one coil queries are handled correctly/Output Value  2 Bytes  0x0000 or 0xFF00"""
            for a in itertools.count():                                                                       
                    address_fuz= random.randint(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS) 

                    fuzz_session.master1.execute_f(slave, WRITE_SINGLE_COIL, address_fuz , output_value=random.randint(0,1))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True   ;sleep(1.0)                  

    def test_readcoil(self):
            """Check that read coil queries are handled correctly, read 1-2000 coil  """                                    
            for a in itertools.count():
                    if (fuzz_session.MAX_COILS-fuzz_session.MIN_COILS) <=5: address_fuz=fuzz_session.MIN_COILS 
                    else:address_fuz= random.randint(fuzz_session.MIN_COILS,(fuzz_session.MAX_COILS-(self.COILS_quantity*2)))
                    fuzz_session.master1.execute_f(slave, READ_COILS, address_fuz, self.COILS_quantity)                                        
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True      

    def test_readhr(self):
            """Check that broadcast Holding register queries are handled correctly
              used to read the contents of a contiguous block of holding registers 1-125
            """ 
            for a in itertools.count():
                    if (fuzz_session.MAX_HO_REG-fuzz_session.MIN_HO_REG) <=5: address_fuz=fuzz_session.MIN_HO_REG
                    else:address_fuz= random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG-(self.HO_REG_quantity)*2)
                    fuzz_session.master1.execute_f(slave,READ_HOLDING_REGISTERS,address_fuz, self.HO_REG_quantity)
                    if fuzz_session.flag_reguest==False :
                       break
            fuzz_session.flag_reguest=True;sleep(1.0) 
    
    
    def test_ReadFifoQueueRequestEncode(self):
            """
            Read Fifo Queue FC : 24 
            Test that response for read ReadFifoQueueRequestEncode function
            """
            for a in itertools.count():
                    address_fuz= random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG) 
                    #Test basic bit message encoding/decoding 
                    handle  = ReadFifoQueueRequest(address_fuz)
                    result  = struct.pack(">B",Read_FIFO_queue)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)
                    lgr.info('answer >> address: %s, response:%r '  % (address_fuz,response))
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 

    
    def test_ReadFileRecordRequestEncode(self):
            ''' 
            Read File Record Request FC : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
            Test basic bit message encoding/decoding 
            The starting record number within the file: 2 bytes-Indicates which record in the file -(starting address)
            The available quantity of Extended Memory files depends upon the installed size
            of Extended Memory in the slave controller. Each file except the last one contains
            10,000 registers, addressed as 0000-270F hexadecimal (0000-9999 decimal)
            The File number: 2 bytes-Indicates which file number -Extended Memory file number: 2 bytes (1 to 10, hex 0001 to 000A)
            '''
            for a in itertools.count():                
                record1  = FileRecord(file_number=0x01, record_number=0x01, record_length=0x02)
                record2  = FileRecord(file_number=0x02, record_number=0x02, record_length=0x04)
                record3  = FileRecord(file_number=0x03, record_number=0x03, record_length=0x02)
                record4  = FileRecord(file_number=0x04, record_number=0x04, record_length=0x04)                                          
                records = [record1,record2,record3,record4]
                handle  = ReadFileRecordRequest(records)
                result  = struct.pack(">B",Read_File_record)+handle.encode()
                response=fuzz_session.master1.execute_fpdu(slave,result)
                records = [fuzz_session.record1,record2,record3,record4]                
                lgr.info('records:%r, response: %r ' % (records, response))                
                if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 
   
   
    def test_WriteFileRecordRequestEncode(self):
            '''
            Write File Record Request FC : 21   file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
            Test basic bit message encoding/decoding 
            '''
            for a in itertools.count():           
                
                record1 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04')
                record2 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x0a\x0e\x04')
                record3 = FileRecord(file_number=0x02, record_number=0x03, record_data=b'\x00\x01\x02\x04')
                record4 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04')                                      
                records = [record1,record2,record3,record4]                
                handle  = WriteFileRecordRequest(records)
                result  = struct.pack(">B",Write_File_record)+handle.encode()
                response=fuzz_session.master1.execute_fpdu(slave,result)                
                lgr.info('records:%r, response: %r ' % ([fuzz_session.record1,record2,record3,record4], response))
                if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True;sleep(1.0) 
    
    def test_MaskWriteRegisterRequestEncode(self):
        '''
        Mask Write Register Request FC:22, param :address=0x0000, and_mask=0xffff, or_mask=0x0000
        This function code is used to modify the contents of a specified holding register 
        The normal response is an echo of the request. The response is returned after the register 
        has been written

        '''

        and_mask= 0x0000                                               # 0x0000 to 0xFFFF random ??
        or_mask= 0xFFFF                                                # 0x0000 to 0xFFFF       
        ''' Test basic bit message encoding '''
        for a in itertools.count():
                address_fuz= random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG)
                and_mask= rand_XShortField()                          # 0x0000 to 0xFFFF random ??
                or_mask = rand_XShortField()
                handle  = MaskWriteRegisterRequest(address_fuz, and_mask, or_mask)
                result  = struct.pack(">B",Mask_Write_Register)+handle.encode()                
                response=fuzz_session.master1.execute_fpdu(slave,result)

                lgr.info('answer >> address_fuzzing: %s, 0x%02X, response: %r'  % (address_fuz,address_fuz,response))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True;sleep(1.0) 
    
    
    def test_ReadWriteMultipleRegistersRequest(self):
        '''
        FC: 23 (0x17): Read/Write Multiple registers 
        This function code performs a combination of one read operation and one write operation in a single MODBUS transaction
        Read Starting Address  2 Bytes  0x0000 to 0xFFFF
        Quantity to Read  2 Bytes  0x0001 to 0x007D /1-125
        Write Starting Address  2 Bytes  0x0000 to 0xFFFF
        Quantity  to Write   2 Bytes  0x0001 to 0X0079  /1-121
        Write Byte Count  1 Byte  2 x N*
        Write Registers Value  N*x 2 Bytes  
        *N  = Quantity to Write

        '''
        
        randByteList = lambda n: [randint(0,65535) for b in range(1,n+1)]           #Random byte List               
        for a in itertools.count():
            if (fuzz_session.MAX_HO_REG-fuzz_session.MIN_HO_REG) <=5: 
                address_read =fuzz_session.MIN_HO_REG  
            else:address_read=random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG-(self.HO_REG_quantity)*2)           
            address_write=random.randint(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG)                                                
            arguments = {
                        'read_address':  address_read, 'read_count': self.HO_REG_quantity,
                        'write_address': address_write, 'write_registers':randByteList (random.randint(0,self.HO_REG_quantity)),    
                        } 
            handle  = ReadWriteMultipleRegistersRequest(**arguments)            
            result = struct.pack(">B",Read_Write_Multiple_Registers)+handle.encode()            
            response=fuzz_session.master1.execute_fpdu(slave,result)           
            lgr.info('Answer >> address_fuzzing: %r, write_address: %r, response: %r' % (address_read,address_write,response))            
            if fuzz_session.flag_reguest==False :
                        break
        fuzz_session.flag_reguest=True;sleep(1.0) 


    def test_Read_Device_Information(self): 
        """
        Read_Device_Information  FC : 43
        This function code allows reading the identification and additional
        information relative to the physical and functional description of a
        remote device, only.
        params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] } 
        handle  = ReadDeviceInformationRequest(**params)'
        """            
        fuzz_session.read_code = self.read_code ;fuzz_session.object_id = self.object_id
        lgr.info('read_code:  0x%02X , object_id: 0x%02X ' % (fuzz_session.read_code,fuzz_session.object_id,))   
        for i in itertools.count():
                handle  = ReadDeviceInformationRequest(fuzz_session.read_code,fuzz_session.object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=fuzz_session.master1.execute_fpdu(slave,result)
                lgr.info('Answer >> fuzz_read_code: 0x%02X, (%d) fuzz_object_id: 0x%02X (%d), response: %r'  % (fuzz_session.read_code,fuzz_session.read_code,fuzz_session.object_id,fuzz_session.object_id,response))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
        sleep(1.0)                    
