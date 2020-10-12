
#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2015
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
#supported modbus_tk functions (8)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_COILS = 15
WRITE_MULTIPLE_REGISTERS = 16 

# add extra function for fuzzer -insert from pymodbus 1.2.0 (module:file_message.py)
#Encapsulated Interface Transport=43       (0x2B) MEI_sub_function_code  13/14
Read_device_Identification = 43
Read_Write_Multiple_Registers = 23           #(0x17)   
Mask_Write_Register = 22                     #(0x16)
Read_FIFO_queue = 24                         #(0x18)
Read_File_record = 20                        #(0x14) 
Write_File_record = 21                       #(0x15)  
Report_Slave_ID = 17                         #(0x11) (Serial Line only)

#modbus exception codes support modbus_tk
ILLEGAL_FUNCTION = 1
ILLEGAL_DATA_ADDRESS = 2
ILLEGAL_DATA_VALUE = 3
SLAVE_DEVICE_FAILURE = 4
SLAVE_DEVICE_BUSY = 6
MEMORY_PARITY_ERROR = 8
ACKNOWLEDGE = 5
NEGATIVE_ACKNOWLEDGE = 7
GATEWAY_PATH_UNAVAILABLE = 10
GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 11

#define for search mapping block/for black-box
s_address=0
l_address=65535
offset_address=65535                       # step from star
step=32768                                 # step for search memory map
quan_step= 1                               # fix step for search map /def chk_list
num_of_search=0
   
#list of supported address   
supported_address_coil = []
supported_address_input_reg = []
supported_address_dist_input = []
supported_address_hold_reg = []

#list of not response address 
not_response_address_coil = []
not_response_address_input_reg = []
not_response_address_dist_input = []
not_response_address_hold_reg = []

#define for function add block/fuzzing 
slave=1
start_address=0
last_address=40000
size_of_bank=9999
offset_fuzzer=0                             # up - down bank memory 
name_of_block=None
value_range=64                              # quantity_of_x how value read 
mem_step=1024                               # how match move to memory -step
FCmergedlist=[]                             #list fc for merge csv config file

#set step for read block memory with memory dump attack
scv_table='dump_memory.csv'
quantity=100
step_mem_dump=100

"""Defaults number of request for each FC """
fuzz_request=200

#Time setting for duration
start_time=0
end_time=0

""" Define value for MIN MAX Address of bank """
MIN_COILS=0
MAX_COILS=0
MIN_IN_REG=0
MAX_IN_REG=0
MIN_DIS_IN=0
MAX_DIS_IN=0
MIN_HO_REG=0
MAX_HO_REG=0

#define for FC 20,21,22
#Each file  contains 10,000 registers, addressed as 0000-270F hexadecimal (0000-9999 decimal).
   
start_address_reco=0
last_address_reco=9999
                                            
#Invalid_trans_IDs (def TransIdIs)
flag_IDs=1                                                              

#global flag_pdu-fuzz pdu send response
flag_pdu=0

#fuzz write multicoil/register /value                                                                  
nu_reg=1                                                                    

#flag for pdu dumple 
z=7                                    
n_rep_pdu=0 
y=1
C=1

#This flag use in function invalid FC in pdu
flag_i=0  