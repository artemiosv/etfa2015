# -*- coding: utf-8 -*-
"""
User-defined Exceptions
Exceptions for Modbus tk ver 1.0
Pymodbus Exceptions 2.4.0 

"""
import modbus_tk.utils
from utils_b import * 
import logging.handlers as handlers

logger = modbus_tk.utils.create_logger("console") #create logger- 
lgr=logging.getLogger('')

#-------------------------------------------------------------------------------
#Exceptions for Modbus tk ver 1.0
#-------------------------------------------------------------------------------

class CsvError(Exception): #use in test-MBAP.py
    """
    Exception raised when trying to get Pairwise CSV, IOError.
    """
    pass


class TestfieldError(Exception): #use in test-MBAP.py
    """
    Exception raised when one argument 
    
    """
    pass


class ModbusError(Exception):  #use mtf.py
    """Exception raised when the modbus slave returns an error"""

    def __init__(self, exception_code, value=""):
        """constructor: set the exception code returned by the slave"""
        if not value:
            value = "Modbus Error: Exception code = %d" % (exception_code)
        Exception.__init__(self, value)
        self._exception_code = exception_code

    def get_exception_code(self):
        """return the exception code returned by the slave (see defines)"""
        return self._exception_code


class ModbusError(Exception):  #not use
    """Exception raised when the modbus slave returns an error"""

    def __init__(self, exception_code, value=""):
        """constructor: set the exception code returned by the slave"""
        if not value:
            value = "Modbus Error: Exception code = %d" % (exception_code)
        Exception.__init__(self, value)
        self._exception_code = exception_code

    def get_exception_code(self):
        """return the exception code returned by the slave (see defines)"""
        return self._exception_code


class WriteError(Exception):   #not use
    """Exception raised when write error csv file"""
    #lgr.warn("Write error ..")
    pass


class ModbusInvalidResponseError(Exception):   #not use
    """
    Exception raised when the response sent by the slave doesn't fit
    with the expected format
    """
    pass


class ValueError (Exception):   
    """
    Exception raised when trying to get an object that doesn't exist
    """
    pass


"""
Pymodbus Exceptions 2.4.0 
Custom exceptions to be used in the Modbus code.
"""


class BaseException(Exception):
    """ Base modbus exception """

    def __init__(self, string):
        """ Initialize the exception
        :param string: The message to append to the error
        """
        self.string = string

    def __str__(self):
        return 'Modbus Error: %s' % self.string

    def isError(self):
        """Error"""
        return True


class IOException(Exception):
    """ Error resulting from data i/o """

    def __init__(self, string="", function_code=None):
        """ Initialize the exception
        :param string: The message to append to the error
        """
        self.fcode = function_code
        self.message = "[Input/Output] %s" % string
        Exception.__init__(self, self.message)


class ParameterException(Exception):
    """ Error resulting from invalid parameter """

    def __init__(self, string=""):
        """ Initialize the exception

        :param string: The message to append to the error
        """
        message = "Invalid Parameter: %s" % string
        lgr.error ("Invalid Parameter: %s" % string)
        Exception.__init__(self, message)


