#!/usr/bin/python3

#class Employee(object):
#    def __init__(self, name, last_name, age):
#        self.name = name
#        self.last_name = last_name
#        self.age = age

#d = {'name': 'Oscar', 'last_name': 'Reyes', 'age':32 }
#e = Employee(**d) 

#print e.name # Oscar 
#print e.age + 10 # 42 
import fuzz_session

#import pandas as pd 

#init class with dictionary of the default values
class dict_fuzz_object(object):
    
    def __init__(self):
               
        self.Dict_lists_of_smart_value = {
	        'foo_value': [0,65535],
	        'foo_fct': [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))],
	        'Common_add_fuz':[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,\
	        16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535],
	        'qua_IN_REG_HO_REG':[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,\
	        32764,32769,65333,65534,65535],
	        'qua_COILS_DIS_IN':[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,\
	        5000,8196,10000,32762,32763,32764,32769,65333,65534,65535] ,
	        'qua_WR_MU_REG_RW_Multiple':[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,\
	        10000,32762,32763,32764,32769,65333,65534,65535],
	        'qua_W_MUL_COILS':[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,\
	        8196,10000,32762,32763,32764,32769,65333,65534,65535],
	        'value_w_fc23': [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,\
	        32769,65533,65534,65535],
	        'value_w_byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, \
	        252, 253, 254, 255],
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
	        'foo_len': [0, 1,2,3,4,5,6,7,8,9,10,255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,\
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
        }  


        #foo_value=self.myDict.get('foo_value')
    
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


           

p=dict_fuzz_object()         

def smart_value_list():
   
   #print(dict_fuzz_object().mydict())
   print(*p.dict_smart_value().items(), sep='\n')
   print(*p.dict_operation().items(), sep='\n')
   print("\n".join("{}:{}".format(k, v) for k, v in p.dict_operation().items()))
   #get key list
   #foo_value=p.myDict.get('foo_value')
   #foo_value=p
   print(sep='\n')

   #call by key dictionary
   #foo_len=p.dict_smart_value_key('foo_len')
   #print(*foo_len, sep = ", ")

   #payload_pdu=p.dict_operation_key('payload_pdu')
   #print(*payload_pdu, sep = ", ")
  
def iner_loop_key():
        for key in p.dict_operation():
            #value =  p.dict_operation_key('key') 
            #value = p.dict_operation()[key] #list
            #fuzz_session[key] = p.dict_operation()[key]  #call of class      
            #fuzz_session +'key' = p.dict_operation_key('key') 
            #fuzz_session.+'key' = p.dict_operation_key('key') 
            
            #print(key, ":", value)
            print(sep='\n')    


smart_value_list()
#iner_loop_key()

#print(d)
#print(*d.items(), sep='\n')
