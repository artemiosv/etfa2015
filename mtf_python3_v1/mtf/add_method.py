
#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2018
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
import random

# from PYMODBUS 2.4.0, utilities.py
# Bit packing functions
def pack_bitstring(bits):
    """ Creates a string out of an array of bits

    :param bits: A bit array

    example::

        bits   = [False, True, False, True]
        result = pack_bitstring(bits)
    """
    ret = b''
    i = packed = 0
    for bit in bits:
        if bit:
            packed += 128
        i += 1
        if i == 8:
            ret += int2byte(packed)
            i = packed = 0
        else:
            packed >>= 1
    if 0 < i < 8:
        packed >>= (7 - i)
        ret += int2byte(packed)
    return ret


def unpack_bitstring(string):
    """ Creates bit array out of a string

    :param string: The modbus data packet to decode

    example::

        bytes  = 'bytes to decode'
        result = unpack_bitstring(bytes)
    """
    byte_count = len(string)
    bits = []
    for byte in range(byte_count):
        if IS_PYTHON3:
            value = byte2int(int(string[byte]))
        else:
            value = byte2int(string[byte])
        for _ in range(8):
            bits.append((value & 1) == 1)
            value >>= 1
    return bits


def make_byte_string(s):
    """
    Returns byte string from a given string, python3 specific fix
    :param s:
    :return:
    """
    if IS_PYTHON3 and isinstance(s, string_types):
        s = s.encode()
    return s


def hex_to_hexstr(input_bytes):
    """
    from boofuz fuzzer library
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    :param input_bytes: Arbitrary bytes.

    :return: Printable string.
    """
    return helpers.hex_str(input_bytes) + " " + repr(bytes(input_bytes))

def _render(self, value):
        """Render string value, properly encoded.
        """
        try:
            # Note: In the future, we should use unicode strings when we mean to encode them later. As it is, we need
            # decode the value before decoding it! Meaning we'll never be able to use characters outside the ASCII
            # range.
            _rendered = str(value).decode('ascii').encode(self.encoding)
        except UnicodeDecodeError:
            # If we can't decode the string, just treat it like a plain byte string
            _rendered = value

        return _rendered

def mutate(self):
    """
    from  /boofuzz-master/   
    Mutate the primitive value returning False on completion.

    @rtype:  bool
    @return: True on success, False otherwise.
     if self.step:
        self.max_mutations = (self.max_length - self.min_length) / self.step + 1
    """

    # select a random length for this string.
    if not self.step:
        length = random.randint(self.min_length, self.max_length)
    # select a length function of the mutant index and the step.
    else:
        length = self.min_length + self._mutant_index * self.step

    # reset the value and generate a random string of the determined length.
    self._value = ""
    for i in xrange(length):
        self._value += chr(random.randint(0, 255))

    # increment the mutation count.
    self._mutant_index += 1

    return True

def num_mutations(self):
    """
    Calculate and return the total number of mutations for this individual primitive.

    @rtype:  int
    @return: Number of mutated forms this primitive can take
    """

    return self.max_mutations

def hex_to_binary(number: 1, num_digits: int = 16) -> str:
    """
    from  /boofuzz-master/
    Converts a hexadecimal value into a string representation
    of the corresponding binary value
    Args:
        hex_number: str hexadecimal value
        num_digits: integer value for length of binary value.
                    defaults to 8
    Returns:
        string representation of a binary number 0-padded
        to a minimum length of <num_digits>
    """
    #return str(bin(int(hex_number, 16)))[2:].zfill(num_digits)
    return str(bin(number))[2:].zfill(num_digits)


def binary_string_to_int(binary):
    """
    from  /boofuzz-master/
    Convert a binary string to a decimal number.

    @type  binary: str
    @param binary: Binary string

    @rtype:  int
    @return: Converted bit string
    """

    return int(binary, 2)


def int_to_binary_string(number, bit_width):
    """
    Convert a number to a binary string.

    @type  number:    int
    @param number:    (Optional, def=self._value) Number to convert
    @type  bit_width: int
    @param bit_width: (Optional, def=self.width) Width of bit string

    @rtype:  str
    @return: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


#-------------------------------------------------------------------------------
#HexByteConversion
#Convert a byte string to it's hex representation for output or visa versa.
#ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
#HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
# test data - different formats but equivalent data
#__hexStr1  = "FFFFFF5F8121070C0000FFFFFFFF5F8129010B"
#__hexStr2  = "FF FF FF 5F 81 21 07 0C 00 00 FF FF FF FF 5F 81 29 01 0B"
#__byteStr = "\xFF\xFF\xFF\x5F\x81\x21\x07\x0C\x00\x00\xFF\xFF\xFF\xFF\x5F\x81\x29\x01\x0B"

#-------------------------------------------------------------------------------
def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    #return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    #return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )                                #not space
    return ''.join( [ "%02X " % x for x in byteStr ] ).strip()                                

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case    
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
 
    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )


#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------
def rand_XShortField():                       # rundom hex 2 bytes
    return random.randint(0,65535)

#use WRITE_MULTIPLE_REGISTERS, WRITE_MULTIPLE_COILS
def rand_XByteField():                        # rundom hex 1 byte
   return random.randint(0,255)

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,256))


def rand_IntEnumField():
   return random.randint(0,256)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)


#convert string to hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)

'''Generate random numbers using the time difference between loop
  iterations.  Quo is 'time' in Latin.'''
           
class Quo:
   
      def __init__(self):
        # Start time for later comparison
        self.start = datetime.now()
     
        # Sleep for a moment to allow `start` - `end` times to not be 0
        sleep(0.01)
     
      def get_raw_bytes(self, _len):
        '''Get raw random bytes, i.e., random bytes prior to hashing.'''
     
        _bytes = []
     
        for i in range(_len):
          byte = []
     
          for i in range(8):
            end = datetime.now()
            bit = int(str((self.start - end).total_seconds())[-1]) % 2
            byte.append(str(bit))
     
          _bytes.append(chr(int(''.join(byte), 2)))
        
        return ''.join(_bytes)
     
      def get_random_bytes(self, _len):
        '''Get truly random bytes, i.e., random bytes post hashing.'''
     
        random_bytes = []
     
        # sha256 wants a minimum input length of 32 bytes.  Since users
        # can request any byte length, round requests up to the nearest
        # 32 byte chunks.
        for i in range(int(ceil(_len / 32.0))):
          raw_bytes = self.get_raw_bytes(32)
     
          random_bytes.append(sha256(raw_bytes).digest())
     
        return ''.join(random_bytes)[:_len]
     
#----------------------------------------------------------------------------------#
#This class implements  BFS or DFS -not use yet
#----------------------------------------------------------------------------------#
class search():
    '''
    The class implements  breadth-first search (BFS) OR Depth-first search (DFS) traversal from a given graph 
     
    '''   
    def __init__(self):            
        #parents = {'N1': ['N2', 'N3', 'N4'], 'N3': ['N6', 'N7'], 'N4': ['N3'], 'N5': ['N4', 'N8'], 'N6': ['N13'],
        #           'N8': ['N9'], 'N9': ['N11'], 'N10': ['N7', 'N9'], 'N11': ['N14'], 'N12': ['N5']}
        parents = dict()
    
        parents = {
        0: [256, 512, 1024, 2048],
        252: [251],
        253: [252],
        254: [253],
        255: [254],
        256: [257, 255],
        257: [258],
        258: [259],
        259: [260],
        260: [261],
        508: [507],
        509: [508],
        510: [509],
        511: [510],
        512: [513, 511],
        513: [514],
        514: [515],
        515: [516],
        516: [517],
        }   

    def DFS_dist_from_node(query_node, parents):

        """Depth-first search: not useReturn dictionary containing distances of parent GO nodes from the query"""
        
        result = {}
        stack = []
        stack.append( (query_node, 0) )
        while len(stack) > 0:
            #print("stack=", int(stack[0][0]))            # check node
            print("stack=", stack)                        #original           
            node, dist = stack.pop()
            result[node] = dist
            if node in parents: 
                for parent in parents[node]:
                    # Get the first member of each tuple, see 
                    # http://stackoverflow.com/questions/12142133/how-to-get-first-element-in-a-list-of-tuples
                    stack_members = [x[0] for x in stack]
                    if parent not in stack_members:
                        stack.append( (parent, dist+1) )
        return result    

    def BFS_dist_from_node(query_node, parents):

        """ breadth-first search :    not use, Return dictionary containing minimum distances of parent GO nodes from the query"""

        result = {}
        queue = []
        queue.append( (query_node, 0) )
        while queue:       
            print("queue=", int(queue[0][0]))              #a node check
            node, dist = queue.pop(0)
            result[node] = dist
            if node in parents:                           # If the node *has* parents
                for parent in parents[node]:
                    # Get the first member of each tuple, see 
                    # http://stackoverflow.com/questions/12142133/how-to-get-first-element-in-a-list-of-tuples
                    queue_members = [x[0] for x in queue]
                    if parent not in result and parent not in queue_members: # Don't visit a second time
                        queue.append( (parent, dist+1) )
                    return result    

  #ver 1.1 /MTF
# Fibonacci numbers module, write Fibonacci series up to n
def fib(n):    
    a, b = 0, 1
    while b < n:
        print(b, end=' ')
        a, b = b, a+b

# return Fibonacci series up to n
def fib2(n): 
    result = []
    a, b = 0, 1
    while b < n:
        result.append(b)
        a, b = b, a+b
    return result


def randstring(length=7):
    valid_letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join((random.choice(valid_letters) for i in range(length)))

        
def random_id(length):
    number = '0123456789'
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    format='%d,%u,%c,%n,%x,%s,\0 '
    id = ''
    for i in range(0,length,3):
        id += random.choice(number)
        id += random.choice(alpha)
        id += random.choice(format)
    return id   

def random_bit(length):
    number = '111111111111111111'
    alpha  = '000000000000000000'
    format='1111111111111111000000000000000001111111111111111000000000'
    id = ''
    for i in range(0,length,3):
        id += random.choice(number)
        id += random.choice(alpha)
        id += random.choice(format)
    return id    

#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------
def rand_XShortField():                       # random hex 2 bytes
    return random.randint(0,65535)

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,256))


def rand_IntEnumField():
   return random.randint(0,256)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)

"""random 0 or 1 """
def rand_binary():
    return random.randint(0,1)


#convert string to hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)


#some def for use ,all def for fuzzer payload adu+pdu copy from unittest.py, --not use
class custom_mbap_pdu() :
    
    def testRequestErrors(self):
        ''' Test a request factory decoder exceptions '''

        for func, msg in self.bad:
            result = self.server.decode(msg)
            self.assertEqual(result.ErrorCode, 1,
                    "Failed to decode invalid requests")
            self.assertEqual(result.execute(None).function_code, func,
                    "Failed to create correct response message")    
  
    def testPack(self):
        """Test that packing a mbap give the expected result"""
        self.assertEqual(self.mbap1.pack(), struct.pack(">HHHB", 1, 2, 3, 4))
    
    def mbap_custom(self):
        """create mbap object custom"""
        mbap = modbus_tcp_b.TcpMbap_b()                            
        mbap.protocol_id = 2
        mbap.length = 0
        mbap.unit_id = 0
       
    def testBuildRequest(self):
        """Test the mbap returned by building a request"""
        query = modbus_tcp.TcpQuery()
        request = query.build_request("", 0)
        self.assertEqual(struct.pack(">HHHB", query._request_mbap.transaction_id, 0, 1, 0), request)
#   
    def testBuildRequestWithSlave(self):
        """Test the mbap returned by building a request with a slave"""
        query = modbus_tcp.TcpQuery()
        for i in range(0, 255):
            request = query.build_request("", i)
            self.assertEqual(struct.pack(">HHHB", query._request_mbap.transaction_id, 0, 1, i), request)

    def InvalidSlave(self):
        """Test that an error is raised when invalid slave is passed"""
        query = modbus_tcp.TcpQuery()
        for i in [256, 257, 65536]:
            self.assertRaises(modbus_tk.modbus.InvalidArgumentError, query.build_request, "", i)

    def testBuildRequestWithPdu(self):
        """Test the mbap returned by building a request with a pdu"""
        query = modbus_tcp.TcpQuery()
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, 0)
            self.assertEqual(struct.pack(">HHHB"+str(len(pdu))+"s", query._request_mbap.transaction_id, 0, len(pdu)+1, 0, pdu), request)
        
    def testParseRespone(self):
        """Test that Modbus TCP part of the response is understood"""
        query = modbus_tcp.TcpQuery()
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request("a", 0)
            response = struct.pack(">HHHB"+str(len(pdu))+"s", query._request_mbap.transaction_id, query._request_mbap.protocol_id, len(pdu)+1, query._request_mbap.unit_id, pdu)
            extracted = query.parse_response(response)
            self.assertEqual(extracted, pdu)

    def testParseRequest(self):
        """Test that Modbus TCP part of the request is understood"""
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, i)
            (slave, extracted_pdu) = query.parse_request(request)
            self.assertEqual(extracted_pdu, pdu)
            self.assertEqual(slave, i)
            i += 1

    def testParseRequestInvalidLength(self):
        """Test that an error is raised if the length is not valid"""
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = struct.pack(">HHHB", 0, 0, (len(pdu)+2), 0)
            self.assertRaises(modbus_tk.modbus_tcp.ModbusInvalidMbapError, query.parse_request, request+pdu)

    def testBuildResponse(self):
        """Test that the response of a req
           mbap.length = fuzzer_ADU().Invalidlen(self)uest is build properly
        """
        query = modbus_tcp.TcpQuery()
        i = 0
        for pdu in ["", "a", "a"*127, "abcdefghi"]:
            request = query.build_request(pdu, i)
            response = query.build_response(pdu)
            response_pdu = query.parse_response(response)
            self.assertEqual(pdu, response_pdu)
            i += 1  
    
    def test_Write_SingleCoilIn_Value(self):
        """Check that an error is raised when writing a coil with an invalid value"""
        bad_query = struct.pack(">BBHH", 1, modbus_tk.defines.WRITE_SINGLE_COIL, 0, 1)
                        
        self.master._send(bad_query)
        response = self.master._recv()
        self.assertEqual(response[:-2], struct.pack(">BBB", 1, modbus_tk.defines.WRITE_SINGLE_COIL+128, 3))       

