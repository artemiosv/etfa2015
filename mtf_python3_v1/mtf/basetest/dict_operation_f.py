#!/usr/bin/env python
# -*- coding: utf-8 -*-

import fuzz_session
from  product.s_primitives import *

#---------------------------------------------------------------------------------------------------------------------------------------
#This class about  dictionary of smart value, interest value and list operation fuzz testing-build the fuzz library.
#smart value, interest value
#[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8195, 8196, 8197, 16383, 16384, 16385, 10000, 20000,
# 32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
# 0xFFFF+2, 99999, 100000, 500000, 1000000]:

#list for fuzzing use  invalid output_value in PDU"""
#foo_value= [0,65535]
#list of smart address for fuzzing --add value 32768 65535 and 10000, 20000,40000, 50000
#Common_add_fuz=[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535]   

#Use to Invalid_quantity, smart value contiguous registers (1 to  123 registers) for 16 (0x10)/"""
#qua_IN_REG_HO_REG=[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]                                 #Quantity   1 to 125 (0x7D)
#qua_COILS_DIS_IN=[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]         #Registers  1 to 2000 (0x7D) 

#23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121"""
#qua_WR_MU_REG_RW_Multiple=[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]
#qua_W_MUL_COILS =[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]

#Quantity  to Write  =121 /fuzze field value
#value_w_fc23= [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65533,65534,65535] 
#value_w_byte_count=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                         
#FC 20 (0x14), FC 21, fc 23 set Configuration interest value for fuzzing field PDU"""
#value_test_refer_type=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 249, 250, 251, 252, 253, 254, 255]                                          #Reference Type                                                #Reference Type list
#value_test_Byte_count=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                                      # normal x07 to 0xF5 /7-245 /one BYTES 
#value_test_file_number=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
#value_test_record_number=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
#value_test_record_length=[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]

#ranges  of PDU : packet 1453 +7 = 1460 B MAX ,max packet 260B
#foo_len= [0,1,2,3,4,5,6,7,8,9,10,255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,1462,1459,1458,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65534,65533,65535]
#FC List for choise fuzzing field PDU for each FC
#Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.User-defined codes in the ranges {65-72, 100-110}
#foo_fct= [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))]

#list operation fuzz testing 
#fp= [ 'repeat','random_pdu','remove','message']
#f_mbap=['len' ,'clone','transId', 'protoId', 'unitId', ]
#payload_pdu=['diagnostics','randByte','randBit','zerobyte','corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception']   
#f_reg=['function_code', 'starting_address', 'quantity_of_x']
#f_wr=['function_code', 'starting_address', 'output_value']
#f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
#f_read_file_rec=['function_code','Byte_Count','Reference_Type','File_number','Record_number','Record_length']
#f_write_file_rec=['Data_length','Reference_Type','File_number','Record_number','Record_length','Record_data']
#f_mask=['function_code', 'and_mask','or_mask']
#f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']
#f_test_FC43=['function_code','mei_type','read_code','object_id' ] 
#------------------------------------------------------------------------------------------------------------------------------------------

class dict_fuzz_object(object):
    
    def __init__(self,b=5, max=65536):
        
        self.max_num=max   
        self.b=b
        #1 to  125 registers, bountery
        #23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write=121  
        self.min_register=1
        self.max_register_R=125
        self.max_register_WFC16=123
        self.max_register_WFC23=121

        self.min_coils=1
        self.max_coils_R=2000
        self.max_coils_W=1968

        self.Dict_lists_of_smart_value = {
            'foo_value': [0,65535],
            'foo_fct': [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))],
            #'Common_add_fuz':[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,\
            #16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535],
            #'Common_add_fuz':bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library,
            'Common_add_fuz':self.interesting_value(),
            #'qua_IN_REG_HO_REG':[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,\
            #32764,32769,65333,65534,65535],

            #Invalid_quantity, smart value contiguous registers (1 to  125 registers) (1 to  121 registers) FC03/ FC04 /FC16/FC23 
            #Rename to Qua_REG
            'qua_IN_REG_HO_REG':self.inter_quantity(self.min_register,self.max_register_R,self.max_register_WFC16,self.b),
             #Rename to Qua_COIL ?
            #'qua_COILS_DIS_IN':[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,\
            #5000,8196,10000,32762,32763,32764,32769,65333,65534,65535] ,
            'qua_COILS_DIS_IN':self.inter_quantity(self.min_coils,self.max_coils_R,self.max_num,self.b),

            #16 (0x10) write a block of contiguous registers (1 to  123  registers)
            #23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity to Write=121    
            #'qua_WR_MU_REG_RW_Multiple':[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,\
            #10000,32762,32763,32764,32769,65333,65534,65535],
            'qua_WR_MU_REG_RW_Multiple':self.inter_quantity(self.min_register,self.max_register_WFC23,self.max_register_R,self.b),

            # Quantity of Registers  2 Bytes  1 to 1968
            #'qua_W_MUL_COILS':[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,\
            #8196,10000,32762,32763,32764,32769,65333,65534,65535],
            'qua_W_MUL_COILS':self.inter_quantity(self.min_coils,self.max_coils_W,self.max_num,self.b),
            #----------------------------------------------------------------------------------------
            #23 /( 0x17) Read_Write_Multiple_Registers
            #field == 'value', output_value=bytearray(random.getrandbits(8) for _ in range(fuzz_session.value_w_fc23[0])) , 
            #'value_w_fc23': [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,\
            #32769,65533,65534,65535],
            'value_w_fc23': self.interesting_value(),
            #Write byte count/1 byte /2*N (Quantity to Write)--replace with interesting value /lib_interesting_256 
            #'value_w_byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, \
            #252, 253, 254, 255],
            'value_w_byte_count':self.lib_interesting_256(),
            #------------------------------------------------------------------------------------------------------------------------------------ 
            'value_test_refer_type':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 249, 250, 251, \
            252, 253, 254, 255],                                                                                         #Reference Type list
            'value_test_Byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, \
            255],                                     
            'value_test_file_number':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, \
            255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767,\
            32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            'value_test_record_number':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, \
            1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            'value_test_record_length':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, \
            125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, \
            16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535],
            
            'foo_len': [0,1,2,3,4,5,6,7,8,9,10, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,\
            1462,1459,1458,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65534,65533,65535],                     
        } 

        self.Dict_fuzz_operation = {                   
            'fp': ['repeat','random_pdu','remove','message'],
            'f_mbap':['len' ,'clone','transId', 'protoId', 'unitId' ],
            'payload_pdu':['diagnostics','randByte','randBit','zerobyte','corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception'],   
            'f_reg':['function_code', 'starting_address', 'quantity_of_x'],
            'f_wr':['function_code', 'starting_address', 'output_value'],
            'f_mul_coil_reg':['function_code', 'starting_address','quantity_of_x','byte_count','value'],
            'f_read_file_rec':['function_code','Byte_Count','Reference_Type','File_number','Record_number','Record_length'],
            'f_write_file_rec':['Data_length','Reference_Type','File_number','Record_number','Record_length','Record_data'],
            'f_mask':['function_code', 'and_mask','or_mask'],
            'f_rw_reg':['function_code', 'read_count','write_count','write_byte_count', 'value'],
            'f_test_FC43':['function_code','mei_type','read_code','object_id' ] 
        }  

    #return dictionary
    def dict_smart_value(self):        
        return self.Dict_lists_of_smart_value
    
    #return key value
    def dict_smart_value_key(self,key):        
        return self.Dict_lists_of_smart_value.get(key)

    #return dictionary
    def dict_operation(self):        
        return self.Dict_fuzz_operation 

    #return key value
    def dict_operation_key(self,key):        
        return self.Dict_fuzz_operation.get(key)

    def add_integer_bound(self, integer,library,b):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.
        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''

        for i in range(-b, +b):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if (0<= case <= self.max_num and self.max_num >0 ) :
                if case not in library:
                    library.append(case)
            elif  (self.max_num <= case <= -self.max_num) :                   
                if case not in library:
                    library(case)      


    def inter_quantity(self,MIN,MAX,OTHER,b) :
        """
        limited number of interests,  use fuzzing parameter PDU
        add item in fuzz library for quauntity
        build the fuzz library for quauantity (min//max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024, -16384 , not boundary [5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        bound for quauantity register and coil,
        remove all empty strings //and dumple item//sort
        if b (bountery) =5 use self.library_simple
        """
        final_list_qua=[];list_qua=[];self.bound=[MIN,MAX,OTHER]    
        for x in self.bound:  
              self.add_integer_bound(x,list_qua,b)

        if b==5:
            self.library_simple=bit_field_simple(0, 16, self.max_num , "<","ascii", True).fuzz_library
            final_list_qua =list_qua+self.library_simple+[5000,10000,20000, 65530, 65531, 65532, 65533, 65534, 65535]
        else :
             self.library=list([x for x in bit_field(0, 16, self.max_num, "<","ascii", True).fuzz_library if x<=(32768+5)])
             final_list_qua =list_qua+self.library+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        
        final_list_qua=list(set(final_list_qua));final_list_qua.sort(reverse=False)
        #return final_list_qua
        return list([x for x in final_list_qua if x<self.max_num ])     

    
    def lib_interesting_256(self):
        """
        integer interesting value up to 256  heuristics library
        negatve integer build  fuzz library. use for byte_count
        field in test_field_PDU and unit_id in MBAP
        case=

        """  
        final_list=[]      
        self.library_simple=bit_field_simple(0, 16, self.max_num , "<","ascii", True).fuzz_library
        final_list =self.library_simple+[250,251,252,253,254]
        final_list=list(set(final_list));final_list.sort(reverse=False)               
        return list([x for x in final_list if x<= 255])     

    def interesting_value(self) :
        """
        limited number of interests,  use fuzzing parameter PDU
        add item in fuzz library for quauntity
        build the fuzz library for quauantity (min//max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024, -16384 , not boundary [5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        bound for quauantity register and coil,
        remove all empty strings //and dumple item//sort
        """
        final_list=[]   
        self.library_simple=bit_field_simple(0, 16, self.max_num, "<","ascii", True).fuzz_library
        final_list =self.library_simple+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        final_list=list(set(final_list));final_list.sort(reverse=False)
        return list([x for x in final_list if x<self.max_num]) 
    

    #to initialize multiple lists-
    def int_smart_value(self):
            fuzz_session.fp= self.dict_smart_value_key('fp')
            fuzz_session.foo_value= self.dict_smart_value_key('foo_value')            
            fuzz_session.Common_add_fuz=self.dict_smart_value_key('Common_add_fuz')
            fuzz_session.qua_IN_REG_HO_REG= self.dict_smart_value_key('qua_IN_REG_HO_REG')                                
            fuzz_session.qua_COILS_DIS_IN=self.dict_smart_value_key('qua_COILS_DIS_IN')
            fuzz_session.qua_WR_MU_REG_RW_Multiple=self.dict_smart_value_key('qua_WR_MU_REG_RW_Multiple')
            fuzz_session.qua_W_MUL_COILS =self.dict_smart_value_key('qua_W_MUL_COILS')
            fuzz_session.value_w_fc23= self.dict_smart_value_key('value_w_fc23')
            fuzz_session.value_w_byte_count=self.dict_smart_value_key('value_w_byte_count')
            fuzz_session.value_test_refer_type=self.dict_smart_value_key('value_test_refer_type')                                                                                         #Reference Type list
            fuzz_session.value_test_Byte_count= self.dict_smart_value_key('value_test_Byte_count')                                     
            fuzz_session.value_test_file_number=self.dict_smart_value_key('value_test_file_number')
            fuzz_session.value_test_record_number=self.dict_smart_value_key('value_test_record_number')
            fuzz_session.value_test_record_length=self.dict_smart_value_key('value_test_record_length')
            fuzz_session.foo_len=self.dict_smart_value_key('foo_len') 
            fuzz_session.foo_fct=self.dict_smart_value_key('foo_fct')

    def int_fuzz_operation(self):                
            fuzz_session.fp= self.dict_operation_key('fp')
            fuzz_session.f_mbap= self.dict_operation_key('f_mbap')
            fuzz_session.payload_pdu=self.dict_operation_key('payload_pdu')   
            fuzz_session.f_reg=self.dict_operation_key('f_reg')
            fuzz_session.f_wr=self.dict_operation_key('f_wr')
            fuzz_session.f_mul_coil_reg=self.dict_operation_key('f_mul_coil_reg')
            fuzz_session.f_read_file_rec=self.dict_operation_key('f_read_file_rec')
            fuzz_session.f_write_file_rec=self.dict_operation_key('f_write_file_rec')
            fuzz_session.f_mask=self.dict_operation_key('f_mask')
            fuzz_session.f_rw_reg=self.dict_operation_key('f_rw_reg')
            fuzz_session.f_test_FC43=self.dict_operation_key('f_test_FC43') 
