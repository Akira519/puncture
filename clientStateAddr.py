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

BUF_SIZE = 32 * 1024

from common import parse_header, onetimeauth_verify, \
    onetimeauth_gen, ONETIMEAUTH_BYTES, ONETIMEAUTH_CHUNK_BYTES, \
    ONETIMEAUTH_CHUNK_DATA_LEN, ADDRTYPE_AUTH

class ClientStateAddr(object):
    def __init__(self, stateControl):
        self._stateControl = stateControl
        self._config = self._stateControl._config
        pass


    def HandleAddr(self, sock, event):
        if event & eventloop.POLL_ERR:
            self._stateControl.destroy()
            return False

        if not self._stateControl._local_sock:
            return False

        data = None
        try:
            data = self._stateControl._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return False
        if not data:
            self._stateControl.destroy()
            return False

        #  self._update_activity(len(data))
        return self.Validation(data)

    def Validation(self,data):
        try:
            data = self._stateControl._cryptor.decrypt(data)
            if not data:
                return False

            header_result = parse_header(data)
            if header_result is None:
                raise Exception('can not parse header')
            addrtype, remote_addr, remote_port, header_length = header_result
            self._stateControl._remote_address = (common.to_str(remote_addr), remote_port)

            if len(data) > header_length:
                self._stateControl._data_to_write_to_remote.append(data[header_length:])

            logging.debug('STAGE_ADDR Validation passed, From: (Ip: %s,port: %s) To(Remote IP: %s,Remote Port:%s), '
                         % (self._stateControl._client_address[0], self._stateControl._client_address[1],remote_addr,remote_port))
            return True
        except Exception as e:
            logging.warn('STAGE_ADDR Validation failed, Ip: %s,port: %s'
                         % (self._stateControl._client_address[0], self._stateControl._client_address[1]))
            # Here we need have measurement to ban if occuring brute force crack  password
            # if the validation fail excess BAN_COUNT of config, invoke iptable to ban IP
            # System will auto release the banned IP if excess BAN_RESUME (minuts) of config
            if self._stateControl._dispatcher._ban_count:
                #self._stateControl._dispatcher.Ban(self._stateControl._client_address[0])
                self._stateControl._dispatcher.Ban(self._stateControl._client_address[0])
            if self._stateControl._config['verbose']:
                traceback.print_exc()
            self._stateControl.destroy()
            return False





