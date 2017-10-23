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
import clientStateControl
import shell
import traceback

from common import parse_header, onetimeauth_verify, \
    onetimeauth_gen, ONETIMEAUTH_BYTES, ONETIMEAUTH_CHUNK_BYTES, \
    ONETIMEAUTH_CHUNK_DATA_LEN, ADDRTYPE_AUTH

class ClientStateDNS(object):
    def __init__(self, stateControl):
        self._stateControl = stateControl
        pass


    def _handle_dns_resolved(self, result, error):
        if error:
            #self._log_error(error)
            self._stateControl.destroy()
            return
        if result and result[1]:
            ip = result[1]
            try:

                remote_addr = ip
                remote_port = self._stateControl._remote_address[1]
                logging.debug('STAGE_DNS resolving Completed, From: (Ip: %s,port: %s) To(Remote IP: %s,Remote Port:%s),'
                             % (self._stateControl._client_address[0], self._stateControl._client_address[1],remote_addr, remote_port))

                self._stateControl.NewRmtSockAndBindEvent(remote_addr, remote_port)
                self._stateControl.StateRotation(None,None)

                return
            except Exception as e:
                shell.print_exception(e)
                if self._stateControl._config['verbose']:
                    traceback.print_exc()
        self._stateControl.destroy()