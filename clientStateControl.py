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
from clientStateAddr import ClientStateAddr
from clientStateDNS import ClientStateDNS
from clientStateConnect import ClientStateConnect
from clientStateStreamPipe import ClientStateStreamPipe


import eventloop
import socket
import errno
import logging
import cryptor
import shell
import time
import weakref

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_CONNECTED = 6
STAGE_STREAM = 5
STAGE_DESTROYED = -1

STREAM_UP = 0
STREAM_DOWN = 1


# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024

class ClientStateControl(object):
    def __init__(self,dispatcher,config,loop,fd_hander_Map,local_sock,dns_resolver):
        self._dispatcher = dispatcher
        self._loop = loop
        self._fd_hander_Map = fd_hander_Map
        self._dns_resolver = dns_resolver
        self._config = config

        self._stateAcceptObj = None
        self._stateAddrObj = None
        self._stateDnsQueryObj = None
        self._stateDnsQueryObj = None
        self._stateStreamPipeOjb = None

        self._remote_sock = None
        self._local_sock = local_sock

        self._remote_address = None
        self._client_address = local_sock.getpeername()[:2]

        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []

        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT

        self._state = STAGE_INIT
        self._stop = False

        self._cryptor = cryptor.Cryptor(config['password'],
                                        config['method'],
                                        config['crypto_path'])

        self._local_sock_status = WAIT_STATUS_READING
        self._remote_sock_status = WAIT_STATUS_INIT

        self.last_activity = 0

        self.InitScenario()

    def PollingSockData(self,sock,status,enable_flag):
        event = eventloop.POLL_ERR
        if enable_flag:
            if status == WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            if status == WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            if status == WAIT_STATUS_READWRITING:
                event |= eventloop.POLL_IN
                event |= eventloop.POLL_OUT
        if sock == self._local_sock and sock:
            self._loop.modify(self._local_sock, event)
        if sock == self._remote_sock and sock:
            self._loop.modify(self._remote_sock, event)

    def NewRmtSockAndBindEvent(self,ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]

        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_hander_Map[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        try:
            remote_sock.connect((ip, port))
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                pass
        self._loop.add(remote_sock, eventloop.POLL_ERR | eventloop.POLL_OUT, self._dispatcher)

    def InitScenario(self):
        self._local_sock.setblocking(False)
        self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self._stateAddrObj = ClientStateAddr(weakref.proxy(self))
        self._stateDnsQueryObj = ClientStateDNS(weakref.proxy(self))
        self._stateConnect = ClientStateConnect(weakref.proxy(self))
        self._stateStreamPipeOjb = ClientStateStreamPipe(weakref.proxy(self))

        self._fd_hander_Map[self._local_sock.fileno()] = self
        self._loop.add(self._local_sock,eventloop.POLL_IN | eventloop.POLL_ERR, self._dispatcher)


    @shell.exception_handle(self_=True, destroy=True)
    def StateRotation(self,sock,event):
        if self._state == STAGE_INIT:
            if self._stateAddrObj.HandleAddr(sock,event):
                self.HeartBeat(self,None)
                self.PollingSockData(self._local_sock, None, False)
                self._state = STAGE_DNS
                self._dns_resolver.resolve(self._remote_address[0], self._stateDnsQueryObj._handle_dns_resolved)
            pass

        elif self._state == STAGE_DNS:
            self.PollingSockData(self._local_sock, WAIT_STATUS_READING, True)

            #20170817 add, support remote sock write&read in same time to improve throughput
            self.PollingSockData(self._remote_sock,WAIT_STATUS_READWRITING,True)

            self._state = STAGE_CONNECTING
            pass
        elif self._state == STAGE_CONNECTING:
            self._stateConnect.HandleConnectRmt(sock,event)
            self.HeartBeat(self, None)
            if self._data_to_write_to_remote:
                self.PollingSockData(self._remote_sock, WAIT_STATUS_WRITING, True)
            else:
                self.PollingSockData(self._local_sock, WAIT_STATUS_READING, True)
                self.PollingSockData(self._remote_sock, WAIT_STATUS_READING, True)
            pass
        elif self._state == STAGE_STREAM:
            self._stateStreamPipeOjb.HandleStreamPipe(sock,event)
            self.HeartBeat(self, None)
            if self._data_to_write_to_remote:
                self.PollingSockData(self._remote_sock,WAIT_STATUS_WRITING,True)
                return

            if self._data_to_write_to_local:
                self.PollingSockData(self._local_sock,WAIT_STATUS_WRITING,True)
                return

            self.PollingSockData(self._local_sock, WAIT_STATUS_READING, True)
            self.PollingSockData(self._remote_sock, WAIT_STATUS_READING, True)

        elif self._state == STAGE_DESTROYED:
                logging.debug('ignore handle_event: destroyed')
        else:
            pass

    def _on_remote_error(self):
            logging.debug('got remote error')
            if self._remote_sock:
                logging.error(eventloop.get_sock_error(self._remote_sock))
            self.destroy()

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
        self.destroy()

    def WriteRemoteSock(self, data):
        sock = self._remote_sock
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            self._data_to_write_to_remote.append(data)
        return True

    def WriteLocalSock(self, data):
        sock = self._local_sock
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            self._data_to_write_to_local.append(data)
        return True

    def HeartBeat(self, handler, data_len):
        #if data_len and self._stat_callback:
        #    self._stat_callback(self._listen_port, data_len)

        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._dispatcher._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._dispatcher._timeouts[index] = None
        length = len(self._dispatcher._timeouts)
        self._dispatcher._timeouts.append(handler)
        self._dispatcher._handler_to_timeouts[hash(handler)] = length


    def destroy(self):
            # destroy the handler and release any resources
            # promises:
            # 1. destroy won't make another destroy() call inside
            # 2. destroy releases resources so it prevents future call to destroy
            # 3. destroy won't raise any exceptions
            # if any of the promises are broken, it indicates a bug has been
            # introduced! mostly likely memory leaks, etc
            if self._state == STAGE_DESTROYED:
                # this couldn't happen
                logging.debug('already destroyed')
                return
            self._state = STAGE_DESTROYED
            if self._remote_sock:
                self._loop.remove(self._remote_sock)
                del self._fd_hander_Map[self._remote_sock.fileno()]
                self._remote_sock.close()
                self._remote_sock = None
            if self._local_sock:
                self._loop.remove(self._local_sock)
                del self._fd_hander_Map[self._local_sock.fileno()]
                self._local_sock.close()
                self._local_sock = None
            self._dns_resolver.remove_callback(self._stateDnsQueryObj._handle_dns_resolved)
            self._dispatcher.remove_handler(self)