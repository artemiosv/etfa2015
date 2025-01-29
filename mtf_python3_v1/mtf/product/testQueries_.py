#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback,itertools,struct,random,logging
from time import * 
import logging.handlers as handlers
import fuzz_session
from add_method  import *
#from module 
from defines import *
from .message import *
from .serial_message import *

lgr=logging.getLogger('') # create logger-

 #------------------------------------------------------------------------------------------------------------------------  
 #read  use function of modbus_tk, script modbus.py, def execute ( ......) , execute_f is similar in modbus_b.py my script
 #vector address and other  is first choice if choice 'Not_fuzz': Fuzzing none, original message send (random)
 #fuzz_session.priority=4
 #------------------------------------------------------------------------------------------------------------------------
class TestQueries():
    global num_diagnostics_request,search_mode, fuzz_mode, MIN_COILS, MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG
    
    def __init__(self,address_COILS=1024,COILS_quantity=2,address_DIS_IN=1024,DIS_IN_quantity=2,address_HO_REG=1024,HO_REG_quantity=2,address_IN_REG=1024,IN_REG_quantity=2,output_value=1,record_length=2,file_number1=3,record_number=256):

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
        self.file_number1=file_number1
        self.file_number2=file_number1
        self.record_number=record_number
        self.record_length=record_length
        self.flag_reguest=True
        self.read_code =0x01
        self.object_id = 0x01

    def test_readcoil(self):
            """Check that read coil queries are handled correctly"""
        
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )//2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (vector_address,self.COILS_quantity))   
            #legal address of legal message 
            fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity                
            for i in itertools.count():
                    # case - legal genarate randomize input test
                    if fuzz_session.priority==4 :                     
                        vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS);self.COILS_quantity = random.randint(1,2000)                     
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity 
                                          
                    fuzz_session.master1.execute_f(slave, READ_COILS,vector_address, self.COILS_quantity)                   
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
    
    def test_ReadAnalogInputs(self):
            """Test that response for read analog inputs (READ_INPUT_REGISTERS) function """ 

            vector_address =(fuzz_session.MIN_IN_REG+fuzz_session.MAX_IN_REG)//2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (self.address_IN_REG,self.IN_REG_quantity))            
            fuzz_session.starting_address= vector_address
            fuzz_session.quantity_of_x=self.COILS_quantity
            for i in itertools.count():
                    ##case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                          vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.IN_REG_quantity = random.randint(1,125)
                          fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.IN_REG_quantity                       
                    fuzz_session.master1.execute_f(slave,READ_INPUT_REGISTERS, vector_address,self.IN_REG_quantity )                                                                 
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)    
            
   
    def test_ReadDiscreteInputs(self):
            """Test that response for read digital inputs function """ 

            vector_address =(fuzz_session.MIN_DIS_IN+fuzz_session.MAX_DIS_IN)//2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % ( vector_address,self.DIS_IN_quantity ))   
            fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.DIS_IN_quantity
            
            for i in itertools.count():              
                    ##case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                        vector_address =random.randint(fuzz_session.MIN_DIS_IN, fuzz_session.MAX_DIS_IN);self.DIS_IN_quantity = random.randint(1,2000)
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.DIS_IN_quantity  
                    fuzz_session.master1.execute_f(slave,READ_DISCRETE_INPUTS,vector_address, self.DIS_IN_quantity)                             
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
            
    
    def test_readhr(self):
            """Test that response for read holding resister -READ_HOLDING_REGISTERS, function """ 
        
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (vector_address,self.HO_REG_quantity ))
            fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.HO_REG_quantity   
                      
            for i in itertools.count():                      
                    # case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                       vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.HO_REG_quantity = random.randint(1,123)
                       fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.HO_REG_quantity 

                    fuzz_session.master1.execute_f(slave,READ_HOLDING_REGISTERS, vector_address, self.HO_REG_quantity )
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        

    
    def test_WriteMultipleHr(self):
            """Check that write WRITE_MULTIPLE_REGISTERS  queries are handled correctly//contiguous registers (1 to  123  registers)"""  
        
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2          
            Mult_output_value=(2*self.HO_REG_quantity)*[self.output_value]
            lgr.info('vector_address: %d ,  vector_quantity_of_x: %d, Mult_output_value: %r ' % (vector_address,self.HO_REG_quantity,Mult_output_value))   
            fuzz_session.starting_address=vector_address
            fuzz_session.quantity_of_x=self.HO_REG_quantity
            for i in itertools.count():         
                    # case - legal genarate randomize input test  
                    if fuzz_session.priority==4 :
                        vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.HO_REG_quantity=random.randint(1,61)   
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.HO_REG_quantity
                        
                    fuzz_session.master1.execute_f(slave, WRITE_MULTIPLE_REGISTERS , vector_address, output_value=(2*self.HO_REG_quantity)*[self.output_value])                                        
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        
    
                  
    def test_WriteMultipleCoils(self):
            """Check that write WRITE_MULTIPLE_COILS queries are handled correctly max 1968 value_out""" 
        
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )//2
            lgr.info('vector_address: %d , Mult_output_value: %d * [%d]' % (vector_address,self.COILS_quantity,self.output_value))
            fuzz_session.starting_address=vector_address
            fuzz_session.quantity_of_x=self.COILS_quantity    
            for i in itertools.count():  
                    if fuzz_session.priority==4 :
                        # case - legal genarate randomize input test  
                        vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS)
                        self.COILS_quantity=random.randint(1,1968)
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity                  
                    fuzz_session.master1.execute_f(slave, WRITE_MULTIPLE_COILS , vector_address , output_value=tuple([self.output_value]*self.COILS_quantity) )
                                  
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        
    
    
    def test_writesingleHr(self):
            """Check that write HOLDING_REGISTERS queries are handled correctly"""
        
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2
            lgr.info('vector_address: %d , output_value: %d' % (vector_address,self.output_value))              
            fuzz_session.starting_address=vector_address
            fuzz_session.output_value=self.output_value
            
            for i in itertools.count():                     
                    # case - legal genarate randomize input test
                    if fuzz_session.priority==4 :
                        vector_address=random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)
                        fuzz_session.starting_address=vector_address
                    fuzz_session.master1.execute_f(slave, WRITE_SINGLE_REGISTER ,vector_address, output_value=self.output_value)
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)         
    
                    
    def test_writecoil(self):
            """Check that write one coil queries are handled correctly//Output Value  2 Bytes  0x0000 or 0xFF00"""
        
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )//2
            lgr.info('vector_address: %d , output_value: %d' % (vector_address,self.output_value))   
            fuzz_session.starting_address=vector_address 
            
            for i in itertools.count() :                                       
                    ##case - legal genarate randomize input test
                    if fuzz_session.priority==4 :  
                       vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS)
                       fuzz_session.starting_address=vector_address 
                    fuzz_session.master1.execute_f(slave, WRITE_SINGLE_COIL, vector_address, output_value=self.output_value)
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)
    
    
    def test_ReadFifoQueueRequestEncode(self):
            """
            Read Fifo Queue  FC : 24 
            the query specifies the starting 4XXXX reference to be read from the FIFO queue
            Test that response for read ReadFifoQueueRequestEncode function
            In a normal response, the byte count shows the quantity of bytes to
            follow, including the queue count bytes and value register bytes
            (but not including the error check field).  The queue count is the
            quantity of data registers in the queue (not including the count register).
            If the queue count exceeds 31, an exception response is returned with an
            error code of 03 (Illegal Data Value).

            """           
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2
            for i in itertools.count():
                    handle  = ReadFifoQueueRequest(vector_address)
                    result  = struct.pack(">B",Read_FIFO_queue)+handle.encode()
                    response=fuzz_session.master1.execute_fpdu(slave,result)                    
                    lgr.info('Answer >> Test Pointer_address: %s response: %r '  % (fuzz_session.Pointer_address,response,))                  
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)            

    
    def test_ReadFileRecordRequestEncode(self):
            """ Read File Record Request FC : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
                Returns the contents of registers in Extended Memory file (6XXXXX) references
                The function can read multiple groups of references. The groups can be separate
                (non–contiguous), but the references within each group must be sequential.
                :params reference_type: Defaults to 0x06 (must be)
                :params file_number: Indicates which file number we are reading
                :params record_number: Indicates which record in the file -(starting address)
                :params record_data: The actual data of the record - 
                :params record_length: The length in registers of the record -(register count)
                :params response_length: The length in bytes of the record
            """        
            
            for i in itertools.count():
                record1  = FileRecord(file_number=0x01, record_number=0x01, record_length=0x02)
                record2  = FileRecord(file_number=0x02, record_number=0x02, record_length=0x04)
                record3  = FileRecord(file_number=0x03, record_number=0x03, record_length=0x02)
                record4  = FileRecord(file_number=0x04, record_number=0x04, record_length=0x04)
                # case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                     record1 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), \
                        record_data=''.join( [chr(255) for i in range(0,random.randint(1,20))]))       
                     record2 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), \
                        record_data=''.join( [chr(255) for i in range(0,random.randint(1,10))]))                                                 
                fuzz_session.f_record1=record1
                records = [record1,record2,record3,record4]
                handle  = ReadFileRecordRequest(records)
                result  = struct.pack(">B",Read_File_record)+handle.encode()
                response=fuzz_session.master1.execute_fpdu(slave,result)
                records = [fuzz_session.f_record1,record2,record3,record4]
                #fuzz_session.f_records=fuzzing records, not  original
                lgr.info('test records (first group-file,record,length): %r - response: %r'  % (records,response,))
                if fuzz_session.flag_reguest==False :
                        break          
            fuzz_session.flag_reguest=True
            sleep(1.0)     

    
    def test_WriteFileRecordRequestEncode(self):
            """
            Write File Record Request FC : 21   
            Writes the contents of registers in Extended Memory file (6XXXXX) references.
            The function can write multiple groups of references. The groups can be separate
            (non–contiguous), but the references within each group must be sequential.
            file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
            The reference type: 1 byte (must be 0x06), The file number: 2 bytes, The starting record number within the file: 2 bytes
            The length of the record to be read: 2 bytes

            """    
            
            for i in itertools.count():
                #case - legal genarate one vector input test
                record1 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04') 
                record2 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x0a\x0e\x04')
                record3 = FileRecord(file_number=0x02, record_number=0x03, record_data=b'\x00\x01\x02\x04')
                record4 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04')
                #case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                     record1 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), \
                        record_data=(''.join( [chr(255) for i in range(0,random.randint(1,20))])).encode() ) 
                        #record_data=(''.join([chr(random.randint(0,255))  for _ in  range()])).encode()) 
                     record2 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999),  \
                        record_data=(''.join( [chr(255) for i in range(0,random.randint(1,10))])).encode() )      
                fuzz_session.f_record1=record1
                records = [record1,record2,record3,record4] 
                handle  = WriteFileRecordRequest(records)
                result  = struct.pack(">B",Write_File_record)+handle.encode()
                response=fuzz_session.master1.execute_fpdu(slave,result)
                records = [fuzz_session.f_record1,record2,record3,record4]               
                lgr.info('test records (first group-file,record,length): %r - response: %r ' % (records, response))
                if fuzz_session.flag_reguest==False :
                    break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
   
    
    def test_MaskWriteRegisterRequestEncode(self):
        """ Mask Write Register Request FC:22 , 
        param :address=0x0000, and_mask=0xffff, or_mask=0x0000
        This function code is used to modify the contents of a specified holding register 
        The normal response is an echo of the request. The response is returned after the register has been written
        """    
        and_mask= 0x0000                                              
        or_mask= 0xFF                                                   
        vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2 
        lgr.info('vector_address: %d, and_mask: %s or_mask: %s' % (vector_address,and_mask,or_mask))   
        fuzz_session.starting_address=vector_address 
        
        for i in itertools.count():
                #case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                    vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)
                    and_mask=random.randint(0,65535);or_mask=random.randint(0,65535);fuzz_session.starting_address=vector_address 
                                    
                handle  = MaskWriteRegisterRequest(vector_address, and_mask, or_mask)
                result  = struct.pack(">B",Mask_Write_Register)+handle.encode()
                response=fuzz_session.master1.execute_fpdu(slave,result)
                lgr.info('Answer >> address: %d  response: %s '  % (fuzz_session.starting_address,(response,)))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
        sleep(1.0)        
    
   
    def test_ReadWriteMultipleRegistersRequest(self):

        """ Read//Write Multiple registers  FC: 23 (0x17)
        This function code performs a combination of one read operation and one write operation in a single MODBUS transaction
        Read Starting Address  2 Bytes  0x0000 to 0xFFFF
        Quantity to Read  2 Bytes  0x0001 to 0x007D //1-125
        Write Starting Address  2 Bytes  0x0000 to 0xFFFF
        Quantity  to Write   2 Bytes  0x0001 to 0X0079  /1-121
        Write Byte Count  1 Byte  2 x N*
        Write Registers Value  N*x 2 Bytes  
        *N  = Quantity to Write
        """    
        #case - legal genarate one vector input test
        address_read =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//2 
        address_write= (fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)//3
        Mult_output_value=self.HO_REG_quantity*[self.output_value]            
        lgr.info('vector_address_read: %d , vector_address_write: %d,vector_quantity_of_x: %d, Mult_output_value: %d * [%d]' % (address_read,address_write,self.HO_REG_quantity ,self.HO_REG_quantity,self.output_value))                 
                             
        for i in itertools.count():
            #case - legal genarate randomize input test 
            if fuzz_session.priority==4 :  
                address_read =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);address_write= random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)             
                self.HO_REG_quantity= random.randint(1,125); self.Write_HO_REG_quantity=random.randint(1,121)
                Mult_output_value=self.Write_HO_REG_quantity*[self.output_value]

            fuzz_session.read_starting_address = address_read
            fuzz_session.write_starting_address= address_write
            
            arguments = {
                        'read_address':  fuzz_session.read_starting_address, 'read_count':self.HO_REG_quantity ,
                        'write_address': fuzz_session.write_starting_address, 'write_registers':Mult_output_value,    
                        } 
            handle  = ReadWriteMultipleRegistersRequest(**arguments)            
            result = struct.pack(">B",Read_Write_Multiple_Registers)+handle.encode()
            response=fuzz_session.master1.execute_fpdu(slave,result)
                
            if fuzz_session.flag_reguest==False :
                break
        fuzz_session.flag_reguest=True
        sleep(1.0)

    
    def test_Read_Device_Information(self):
        """
        Read_Device_Information  FC : 43
        This function code allows reading the identification and additional
        information relative to the physical and functional description of a
        remote device, only.
        params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] } 
        handle  = ReadDeviceInformationRequest(**params)'
        """            
        read_code = self.read_code 
        object_id = self.object_id
        lgr.info('read_code:  0x%02X , object_id: 0x%02X ' % (read_code,object_id,))   
        for i in itertools.count():
                #case - legal genarate randomize input test
                if fuzz_session.priority==4:read_code=random.randint(1,4);object_id=random.randint(0,255)                  
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=fuzz_session.master1.execute_fpdu(slave,result)
                lgr.info('Answer >> read_code: 0x%02X (%d) object_id: 0x%02X (%d) response: %r'  % (fuzz_session.read_code,fuzz_session.read_code,fuzz_session.object_id,fuzz_session.object_id,response))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
        sleep(1.0)            
 