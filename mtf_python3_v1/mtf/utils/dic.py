#!/usr/bin/python3
import itertools
import pandas as pd 
'''
#list of smart address for fuzzing --add value 32768 65535 and 10000, 20000,40000, 50000
Common_add_fuz=[0,1,2,3,4,254,255,256,257,511,512,513,1023,1024,1025,2047,2048,2049,4095,4096,4097,8195,8196,8197,16383,16384,16385,32762,32763,32764,32769,65531,65532,65533,65534,65535]   

#Use to Invalid_quantity, smart value contiguous registers (1 to  123 registers) for 16 (0x10)/
qua_IN_REG_HO_REG=[0,1,2,3,64,123,124,125,126,127,511,512,513,1024,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]                                 #Quantity   1 to 125 (0x7D)
'qua_COILS_DIS_IN':[0,1,2,3,64,123,124,125,126,127,511,512,513,1000,1998,1999,2000,2001,2002,2047,2048,2049,4095,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]         #Registers  1 to 2000 (0x7D) 

#23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121
"qua_WR_MU_REG_RW_Multiple':[0,1,2,3,63,64,119,120,121,122,123,124,125,126,127,511,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]
"qua_W_MUL_COILS' :[0,1,2,3,64,123,124,125,126,127,511,512,513,984,1966,1967,1968,1999,2000,2001,2002,2047,2048,4096,4097,5000,8196,10000,32762,32763,32764,32769,65333,65534,65535]

#Quantity  to Write =121 /fuzze field value
'value_w_fc23': [0,1,2,64,119,120,122,123,121,122,123,124,125,512,513,1024,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65533,65534,65535] 
'value_w_byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                         

#FC 20 (0x14), FC 21, fc 23 set Configuration interest value for fuzzing field PDU
'value_test_refer_type':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 249, 250, 251, 252, 253, 254, 255]                                          #Reference Type                                                #Reference Type list
'value_test_Byte_count':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]                                      # normal x07 to 0xF5 /7-245 /one BYTES 
'value_test_file_number':[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
'value_test_record_number':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
'value_test_record_length':[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]

#ADU 1453 +7 = 1460 B MAX ,max packet 260B
'foo_len'= [0, 1,2,3,4,5,6,7,8,9,10,255,256,257,258,259,260,261,262,263,264,511,512,513,1024,2048,2049,1452,1451,1454,1455,1461,1462,1459,1458,2048,2049,4096,4097,5000,8196,10000,32762,32763,32764,32769,65534,65533,65535]


FC List
Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.
User-defined codes in the ranges {65-72, 100-110} 

flag_i=0  
'foo_fct': [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))]

#List for choise fuzzing field PDU for each FC

fp= [ 'repeat','random_pdu','remove','message']
f_mbap=['len' ,'clone','transId', 'protoId', 'unitId', ]
payload_pdu=['diagnostics','randByte','randBit','zerobyte','corrupt_bytes','corrupt_bits','little_endian_payload','sendbad', 'sendresponse','exception']   
f_reg=['function_code', 'starting_address', 'quantity_of_x']
f_wr=['function_code', 'starting_address', 'output_value']
f_mul_coil_reg=['function_code', 'starting_address','quantity_of_x','byte_count','value']
f_read_file_rec=['function_code','Byte_Count','Reference_Type','File_number','Record_number','Record_length']
f_write_file_rec=['Data_length','Reference_Type','File_number','Record_number','Record_length','Record_data']
f_mask=['function_code', 'and_mask','or_mask']
f_rw_reg=['function_code', 'read_count','write_count','write_byte_count', 'value']


# dictionary of lists  of smart address for fuzzing --add value 32768 65535 and 10000, 20000, 40000, 50000 
#--Use to Invalid_quantity, smart value contiguous registers (1 to  123 registers) for 16 (0x10)/
#qua_IN_REG_HO_REG and qua_COILS_DIS_IN
#--#23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write=121

#--FC 23 Quantity  to Write =121 /fuzze field value and byte count

#FC 20 (0x14), FC 21, fc 23 set Configuration interest value for fuzzing field PDU

#Fuzzing len, ADU 1453 +7 = 1460 B MAX and max packet 260B
'''
Dict_lists_of_smart_value  = {
        'foo_value': [0,65535],
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
Dict_fuzz_operation = {
        'foo_value': [0,65535],
        'foo_fct': [0,(7,8,9,11,12,17,43),list(range(65,73)),list(range(100,110)),list(range(111,128)),list(range(73,80)),list(range(1,65))],
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

#df = pd.DataFrame(myDict) 
#d
#print(myDict)  
#print("The original dictionary is : " + str(myDict))
print(*Dict_fuzz_operation.items(), sep='\n')

foo_value=Dict_lists_of_smart_value.get('foo_value')
foo_fct=Dict_fuzz_operation.get('foo_fct')
#print (*foo_value)
#print(*Dict_lists_of_smart_value , sep = ", ") 
#print('[',end='');print(foo_value, sep=', ', end='');print(']')

#print(*Dict_fuzz_operation , sep = ", ")

print (foo_fct) 
#0, (7, 8, 9, 11, 12, 17, 43), [65, 66, 67, 68, 69, 70, 71, 72], [100, 101, 102, 103, 104, 105, 106, 107, 108, 109], \
#[111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127], [73, 74, 75, 76, 77, 78, 79], \
#[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64]]

print (foo_value)

# A list of the keys of dictionary
list_keys = [ k for k in Dict_fuzz_operation  ]
 
# or a list of the values
list_values = [ v for v in Dict_fuzz_operation.values() ]
 
# or just a list of the list of key value pairs
list_key_value = [ [k,v] for k, v in Dict_fuzz_operation.items() ]


print(sep='\n')

print(list_key_value)
#df = pd.DataFrame(Dict_fuzz_operation)


"""Iterate over the dictionary using for loop
for key in wordFrequency:
    value = wordFrequency[key]
    print(key, " :: ", value)

    out 
    qua_W_MUL_COILS : [0, 1, 2, 3, 64, 123, 124, 125, 126, 127, 511, 512, 513, 984, 1966, 1967, 1968, 1999, 2000, 2001, 2002, 2047, 2048, 4096, 4097, 5000, 8196, 10000, 32762, 32763, 32764, 32769, 65333, 65534, 65535]

"""
def iner_loop_key():
        for key in Dict_lists_of_smart_value:           
            value = Dict_lists_of_smart_value[key]
            #key = Dict_lists_of_smart_value[key]            # for key and list value        
            #print(fuzz_session.key)
            print(key, ":", value)
            print(sep='\n')
prob_list = [('payload', 0.3), ('field_ADU', 0.1), ('field pdu', 0.4),('two fields in message', 0.1),('Not_fuzz',0.1)]

iner_loop_key()
print(prob_list)  