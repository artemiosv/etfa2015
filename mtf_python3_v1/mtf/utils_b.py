#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Modbus TestKit: Implementation of Modbus protocol in python

 (C)2009 - Luc Jean - luc.jean@gmail.com
 (C)2009 - Apidev - http://www.apidev.fr

 This is distributed under GNU LGPL license, see license.txt
"""

import threading
import logging
import socket
import select
import modbus_tk.utils as utils


def threadsafe_fun(fcn):
    """decorator making sure that the decorated function is thread safe"""
    lock = threading.Lock()
    def new(*args, **kwargs):
        """lock and call the decorated function"""
        lock.acquire()
        try:
            ret = fcn(*args, **kwargs)
        except Exception as excpt:
            raise excpt
        finally:
            lock.release()
        return ret
    return new

def flush_socket_b(socks, lim=0):
    """remove the data present on the socket"""
    input_socks = [socks]
    cnt = 0
    while 1:
        i_socks, o_socks, e_socks = select.select(input_socks, input_socks, input_socks, 0.0)
        if len(i_socks)==0:
            break
        for sock in i_socks:
            sock.recv(1024)
        if lim>0:
            cnt += 1
            if cnt>=lim:
                #avoid infinite loop due to loss of connection
                raise Exception("flush_socket: maximum number of iterations reached")
                
def get_log_buffer_b(prefix, buff):
    """Format binary data into a string for debug purpose"""
    log = prefix
    for i in buff:
        log += str(ord(i)) + "-"
    return log[:-1]                