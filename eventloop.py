#!/usr/bin/env python
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import os
import select
import socket
import errno
import logging
from collections import defaultdict

POLL_NULL = 0x00
POLL_IN = 0x01
POLL_OUT = 0x04
POLL_ERR = 0x08
POLL_HUP = 0x10
POLL_NVAL = 0x20

TIMEOUT_PRECISION = 10

EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}

class SelectLoop(object):
    def __init__(self):
        self._r_list = set()
        self._w_list = set()
        self._x_list = set()

    def poll(self, timeout):
        r, w, x = select.select(self._r_list, self._w_list, self._x_list,
                                timeout)
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        return results.items()

    def register(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def unregister(self, fd):
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify(self, fd, mode):
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        pass


class Eventloop(object):
    def __init__(self):
        self.aa = {}
        self._stop = False
        # only support epoll mode, here to initalize epoll model
        if hasattr(select,'epoll'):
            self._impl = select.epoll()
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
          #  pass
        else:
            raise Exception('current OS dont support epoll,system halt')

        logging.debug('epoll initalize successfully')

        # mapping fd and handler
        self._fd_hander_Map = {}

        # Retrieve file descriptor,append map and register epoll service
        # obj map:  
        #       key:   file descriptor
        #       value: {obj,objhandler} 
    def add(self,f,mode,handler):
        fd = f.fileno()
        self._fd_hander_Map[fd] = (f,handler)
        self._impl.register(fd,mode)

        # Remove from file descriptor map& unregister epoll event
    def remove(self,f):
        fd = f.fileno()
        del self._fd_hander_Map[fd]
        self._impl.unregister(fd)

    def stop(self):
        self._stop = True

    def poll(self,timeout=None):
        events = self._impl.poll(timeout)
        return [(self._fd_hander_Map[fd][0],fd,event) for fd,event in events]

    def stop(self):
        self._stop = True

    def modify(self, f, mode):
        fd = f.fileno()
        self._impl.modify(fd, mode)

    def execute(self):
        eventObjArray = []

        while not self._stop:
            try:
                # to-do, set epoll timeout = 5 secs, will add time out control later
                eventObjArray = self._impl.poll(10)
            except(OSError,IOError) as e:
                pass
            # loop eventobj array ,retrieve handler of map and pass f,fd,mode to invoke
            for fd,event in eventObjArray:
                handlerTutle = self._fd_hander_Map.get(fd)
                if handlerTutle:
                    handler = handlerTutle[1]
                    try:
                        handler.dispatcher(handlerTutle[0], fd, event)
                    except (OSError, IOError) as e:
                        pass
                        #shell.print_exception(e)

# from tornado
def errno_from_exception(e):
    """Provides the errno from an Exception object.
    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """
    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None

# from tornado
def get_sock_error(sock):
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
