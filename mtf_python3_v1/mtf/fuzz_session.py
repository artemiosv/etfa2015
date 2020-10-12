#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Share global variables across modules """
fct= [] 
fuzz_mode =False
search_mode=False

#for read pcap file
pcap_mode=False

#calculate fuzz  address for FC , calc for start,end last address bank
fuzz_addre_COILS=[]                                          #
fuzz_addre_DIS_IN=[]
fuzz_addre_IN_REG=[]
fuzz_addre_HO_REG=[]

#Total number of request, 
num_of_request=0

#Counter number of request for each FC def=200
num_of_fc=0
count_num_of_fc=0
flag_reguest=True

#define for search mapping block/for black-box
s_address=0
l_address=65535
step=32768

#define for memory dump attack
quantity=100 

#Prepare fuzz two fields in message'
fuzz_two_fields=False
#For the FC 20,21

record1='FileRecord(file=%d, record=%d, length=%d)' % (0,0,0)

'''This class about  dictionary of smart value, interest value and list operation fuzz testing
list for fuzzing use  invalid output_value in PDU"
foo_value= []
list of smart address for fuzzing --add value 32768 65535 and 10000, 20000,40000, 50000
Common_add_fuz=[]   
Use to Invalid_quantity, smart value contiguous registers (1 to  123 registers) for 16 (0x10), 
Quantity   1 to 125 (0x7D),#Registers  1 to 2000 (0x7D) """
qua_IN_REG_HO_REG=[]                                
qua_COILS_DIS_IN=[]         
23 (0x17) Read/Write Multiple registers/Quantity to Read=125/Quantity  to Write  =121
qua_WR_MU_REG_RW_Multiple=[]
qua_W_MUL_COILS =[]
Quantity  to Write  =121 /fuzze field value
value_w_fc23= [] 
value_w_byte_count=[]                         
FC 20 (0x14), FC 21, fc 23 set Configuration interest value for fuzzing field PDU
value_test_refer_type=[]                                          
value_test_Byte_count=[]                                      
value_test_file_number=[]
value_test_record_number=[]
value_test_record_length=[]
ranges  of PDU ADU 1453 +7 = 1460 B MAX ,max packet 260B"""
foo_len= []
FC List for choise fuzzing field PDU for each FC
#Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.
#User-defined codes in the ranges {65-72, 100-110} 
foo_fct= []
'''
#List for choise fuzzing field PDU for each FC
fp= []
f_mbap=[]
payload_pdu=[]   
f_reg=[]
f_wr=[]
f_mul_coil_reg=[]
f_read_file_rec=[]
f_write_file_rec=[]
f_mask=[]
f_rw_reg=[]
foo_value= []
Common_add_fuz=[]   
qua_IN_REG_HO_REG=[]                                
qua_COILS_DIS_IN=[]         
qua_WR_MU_REG_RW_Multiple=[]
qua_W_MUL_COILS =[]
value_w_fc23= [] 
value_w_byte_count=[]                         
value_test_refer_type=[]                                          
value_test_Byte_count=[]                                      
value_test_file_number=[]
value_test_record_number=[]
value_test_record_length=[]
foo_len= []
foo_fct= []

#add for loop send valid if not response socket
socket_flag=False
stimeout=0
valid_flag=False
sendvalid=0
num_recon=0
receive_flag=False
receive_timeout=0
init_num_rec=0
num_recon_nrec=0
