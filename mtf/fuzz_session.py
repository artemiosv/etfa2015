#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Share global variables across modules """
#FC List
#Public codes the non-continuous ranges {1-64, 73-99, 111-127}.
#User-defined codes in the ranges {65-72, 100-110} """
fct= [] 
#fuzz = True
fuzz_mode =False
search_mode=False

################### for read pcap file ##############
pcap_mode=False
#####################################################
#######calculate fuzz  address for FC ###############
fuzz_addre_COILS=[]                                          #calc for start,end last address bank
fuzz_addre_DIS_IN=[]
fuzz_addre_IN_REG=[]
fuzz_addre_HO_REG=[]

#define for num_of_reguest
num_of_reguest=0

#define for search mapping block/for black-box
s_address=0
l_address=65535
step=32768

#define for memory dump attack
quantity=100  
