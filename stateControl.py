
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
import errno
import logging
import os
import socket
import sys
import time

import asyncdns
import eventloop
import shell

import weakref


import gc
#import objgraph

from clientStateControl import ClientStateControl

TIMEOUTS_CLEAN_SIZE = 512
TIMEOUT_PRECISION = 10

class ServerStateControl(object):
    def __init__(self,config,loop):
        self._loop = loop
        self._fd_hander_Map = {}

        self._server_socket = None
        self._config = config
        self._stop = False
        self._asyncdns = None
        self._dns_sock = None

        listen_addr = config['server']
        listen_port = config['server_port']

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        self._listen_port = listen_port
        addrs = socket.getaddrinfo(listen_addr, listen_port, 0, 
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception('get addrinfo error, listen_addr: %s, listen_port: %d',listen_addr,listen_port)

        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        server_socket.listen(1024)

        self._server_socket = server_socket

        self._connect_client = {}

        self._last_time = time.time()
        self._periodic_callbacks = []

        self._ban_count = None
        if config.get('ban_count',None):
            self._ban_count = int(config['ban_count'])
        self._ban_resume_time = None
        if config.get('ban_resume',None):
            self._ban_resume_time = int(config['ban_resume'])

        self._ips = {}
        self._banned = set()

        self._fd_hander_Map[self._server_socket.fileno()] = self
        self._loop.add(self._server_socket,eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self.add_periodic(self.IdleSockClean)

        self.InitDNS()
        self.InitIptables()

    def InitIptables(self):
        cmd = 'sudo iptables -F PUNCTURE ;sudo iptables -X PUNCTURE ;sudo iptables -N PUNCTURE ;sudo iptables -D INPUT -j PUNCTURE '
        os.system(cmd)
        cmd = 'sudo iptables -I INPUT -j PUNCTURE ;sudo iptables -I PUNCTURE -j RETURN'
        os.system(cmd)

    def InitDNS(self):
        self._asyncdns = asyncdns.DNSResolver(None, self._config['prefer_ipv6'])
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._dns_sock.setblocking(False)
        self._loop.add(self._dns_sock, eventloop.POLL_IN, self._asyncdns)
        self._asyncdns.setSock(self._dns_sock)

    def add_periodic(self, callback):
        self._periodic_callbacks.append(callback)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def IdleSockClean(self):
        if self._stop:
            if self._server_socket:
                self._loop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._server_socket)
            if not self._fd_hander_Map:
                logging.info('stopping')
                self._loop.stop()
        self._sweep_timeout()
        self._ReleaseBan()
        logging.debug('!!!!!!!!!!_fd_hander_Map: %s, loop._fd_hander_Map: %s,' % (len(self._fd_hander_Map), len(self._loop._fd_hander_Map)))

    def Ban(self,ip):
        now = time.time()
        if ip not in self._ips:
            self._ips[ip] =[1,now]
            print(ip)
            sys.stdout.flush()
        else:
            if ip not in self._banned:
                self._ips[ip][0] += 1
                self._ips[ip] = [self._ips[ip][0],now]
        if ip not in self._banned and self._ips[ip][0] >= self._ban_count:
            self._banned.add(ip)
            logging.debug('!!!!!!!!!!banned IP %s' % (ip))
            cmd = 'sudo iptables -I PUNCTURE -s %s -j DROP' % ip
            os.system(cmd)

    def _ReleaseBan(self):
        if self._ban_count:
            now = time.time()

            sNeedRemoved = set()
            for ip in self._banned:
                BannedStruct = self._ips[ip]
                if int(now - BannedStruct[1]) > self._ban_resume_time * 60:
                    logging.debug('!!!!!!!!!!remove banned IP %s' % (ip))
                    sNeedRemoved.add(ip)
                    del self._ips[ip]
                    cmd = 'sudo iptables -D PUNCTURE -s %s -j DROP' % ip
                    os.system(cmd)
            for ip in sNeedRemoved:
                self._banned.remove(ip)
            sNeedRemoved.clear()

    def _sweep_timeout(self):
        if self._timeouts:
         #   logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            logging.debug('!!!!!!!!!!1_sweep_timeout  length %s' % (length))
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler._remote_address:
                            logging.warn('timed out: %s:%d' %
                                         handler._remote_address)
                        else:
                            logging.warn('timed out')
                        logging.info('!!!!!!!!!!1_sweep_timeout  state: %s,remote sock: %s,local sock:%s' \
                                         % (handler._state, handler._remote_sock, handler._local_sock))
                        conn_handler = handler._local_sock
                        conn_IP = handler._client_address
                        handler.destroy()
                        if conn_handler:
                            del self._connect_client[conn_handler]
                            logging.debug('Deleting connection client obj: Ip:  %s, Port: %s' %(conn_IP[0],conn_IP[1]))
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos


    def dispatcher(self,sock,fd,event):
        if sock:
            # logging.log(shell.VERBOSE_LEVEL, 'fd %d %s', fd,
            #            eventloop.EVENT_NAMES.get(event, event))
            pass
        # handle epolling event:
        #### if current file obj == server socket, indicate now client conn made,
        #### else retrieve tcp stream from handler map.
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('server_socket error')

            try:
                conn = self._server_socket.accept()
                self._connect_client[conn[0]] = ClientStateControl(weakref.proxy(self),self._config,weakref.proxy(self._loop),self._fd_hander_Map,conn[0],weakref.proxy(self._asyncdns))
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    pass
        else:
            if sock:
                handler = self._fd_hander_Map.get(fd, None)
                if handler:
                    try:
                        handler.StateRotation(sock, event)
                    except (OSError, IOError) as e:
                        shell.print_exception(e)
            else:
                pass

    def Pump(self):
        while not self._stop:
            asap = False
            try:
                # to-do, set epoll timeout = 5 secs, will add time out control later
                eventObjArray = self._loop._impl.poll(TIMEOUT_PRECISION)
            except(OSError,IOError) as e:
                if eventloop.errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal
                    # handles them as soon as possible
                    asap = True
                    logging.debug('poll:%s', e)
                else:
                    logging.error('poll:%s', e)
                    import traceback
                    traceback.print_exc()
                    continue
            # loop eventobj array ,retrieve handler of map and pass f,fd,mode to invoke
            for fd,event in eventObjArray:
                handlerTutle = self._loop._fd_hander_Map.get(fd)
                if handlerTutle:
                    handler = handlerTutle[1]
                    try:
                        handler.dispatcher(handlerTutle[0], fd, event)
                    except (OSError, IOError) as e:
                        shell.print_exception(e)

            now = time.time()
            if asap or now - self._last_time >= TIMEOUT_PRECISION:
                for callback in self._periodic_callbacks:
                    callback()
                self._last_time = now
        pass





