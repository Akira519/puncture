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
import eventloop
import socket
import errno
import logging
import shell, common
import traceback
import clientStateControl

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_CONNECTED = 6
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING


#BUF_SIZE = 32 * 1024

class ClientStateStreamPipe(object):
    def __init__(self,stateControl):
        self._stateControl = stateControl
        pass

    def HandleStreamPipe(self,sock,event):
        if sock == self._stateControl._remote_sock:
            if event & eventloop.POLL_ERR:
                self._stateControl._on_remote_error()
                if self._stateControl._state == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stateControl._state == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._stateControl._local_sock:
            if event & eventloop.POLL_ERR:
                self._stateControl._on_local_error()
                if self._stateControl._state == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stateControl._state == STAGE_DESTROYED:
                    return
                if event & eventloop.POLL_OUT:
                    self._stateControl._on_local_write()


    def _on_local_read(self):
        if not self._stateControl._local_sock:
            return

        data = None
        try:
            data = self._stateControl._local_sock.recv(clientStateControl.BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self._stateControl.destroy()
            return
        data = self._stateControl._cryptor.decrypt(data)
        if not data:
            return
        logging.debug('STAGE_STREAM local_read and _write_to_remotesock: From(Ip: %s,Port: %s) To (Remote IP: %s, port: %s)'
                      % (self._stateControl._client_address[0],self._stateControl._client_address[1], self._stateControl._remote_address[0], self._stateControl._remote_address[1]))
        self._stateControl.WriteRemoteSock(data)

    def _on_remote_write(self):
        if self._stateControl._data_to_write_to_remote:
            data = b''.join(self._stateControl._data_to_write_to_remote)
            self._stateControl._data_to_write_to_remote = []
         #   logging.info('STAGE_STREAM _on_remote_write, state: %s and _write_to_remotesock:%s ' % (self._stateControl._state,self._stateControl._remote_sock))
            self._stateControl.WriteRemoteSock(data)
        else:
           self._stateControl.PollingSockData(self._stateControl._local_sock,WAIT_STATUS_READING,True)
         #  logging.info('STAGE_STREAM----------_on_remote_write _remote_sock event POLL_OUT no write data,sock: %s' % (self._stateControl._local_sock))

    def _on_remote_read(self):
        # handle all remote read eve nts
        data = None
        try:
            data = self._stateControl._remote_sock.recv(clientStateControl.BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self._stateControl.destroy()
            return
        #self._update_activity(len(data))
        data = self._stateControl._cryptor.encrypt(data)
        try:
           # logging.info('STAGE_STREAM _on_remote_read , state: %s write to local sock: %s' % (self._stateControl._state, self._stateControl._local_sock))
            #self._stateControl._write_to_sock(data, self._stateControl._local_sock)
           logging.debug('STAGE_STREAM remote_read and _write_to_local: From(Remote Ip: %s,Port: %s) To (IP: %s, port: %s) '
                         % (self._stateControl._remote_address[0], self._stateControl._remote_address[1],self._stateControl._client_address[0],self._stateControl._client_address[1]))
           self._stateControl.WriteLocalSock(data)
        except Exception as e:
            shell.print_exception(e)
            if self._stateControl._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self._stateControl.destroy()
