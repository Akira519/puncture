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
import tcphandle
import asyncdns

class Tcpdispatcher(object):
    def __init__(self,config,eventloop):
        self._fd_handler_map = {}
        self._eventloop = None
        self._server_socket = None
        self._config = config
        self._stop = False
        self._asyncdns = asyncdns.DNSResolver(None,config['prefer_ipv6'])
      #  self._asyncdns = dns
        self._tst = False

        listen_addr = config['listen_addr']
        listen_port = config['listen_port']
        addrs = socket.getaddrinfo(listen_addr, listen_port, 0, 
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception('get addrinfo error, listen_addr: %s, listen_port: %d' % (listen_addr,listen_port))

        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        server_socket.listen(1024)

        self._server_socket = server_socket
        self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._dns_sock.setblocking(False)
        self.bindDispatcherEvent(eventloop)

        logging.info('Completed Tcpdispatcher initalization: service ip: %s, ip: %s' % (listen_addr ,listen_port))

    def setTst(self,Tst):
        self._tst = Tst

    def getDNS(self):
        return self._asyncdns

    def bindDispatcherEvent(self,event_loop):
        if self._eventloop:
            raise Exception("bindEventloop failed, already event loop")
        if self._stop:
            raise Exception("bindEventloop failed, Tcp dispather is stopped")

        self._eventloop = event_loop
        self._eventloop.add(self._server_socket,eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add(self._dns_sock, eventloop.POLL_IN, self._asyncdns)
        self._asyncdns.setSock(self._dns_sock)

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
                logging.debug('accept')
                conn = self._server_socket.accept()
                #if self._tst == True:
                #    return

                #TCPRelayHandler(self, self._fd_to_handlers,
                #                self._eventloop, conn[0], self._config,
                #                self._dns_resolver, self._is_local)
                aaa = tcphandle.Tcphandle(self._config, self, self._eventloop, conn[0], self._fd_handler_map)
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    pass
        else:
            if sock:
                handler = self._fd_handler_map.get(fd, None)
                if handler:
                    handler.handle_TCPTXN(sock, event)
            else:
                pass

    def close(self, next_tick=False):
        logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            for handler in list(self._fd_handler_map.values()):
                handler.destroy()