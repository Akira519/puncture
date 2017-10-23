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
import encrypt
import shell, common
import traceback

from common import parse_header, onetimeauth_verify, \
    onetimeauth_gen, ONETIMEAUTH_BYTES, ONETIMEAUTH_CHUNK_BYTES, \
    ONETIMEAUTH_CHUNK_DATA_LEN, ADDRTYPE_AUTH

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024

class Tcphandle(object):
    def __init__(self,config,dispatcher,loop,local_sock,fd_handler_map):
        self._dispatcher = dispatcher
        self._asyncdns = dispatcher.getDNS()
        self._config = config
        self._stop = False
        self._stage = STAGE_INIT
        self._eventloop = None

        self._dns_resolver = self._asyncdns
        self._local_sock = local_sock
        self._remote_sock = None
        self._client_address = local_sock.getpeername()[:2]

        self._fd_handler_map = fd_handler_map
        self._fd_handler_map[self._local_sock.fileno()] = self

        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []

        self._encryptor = encrypt.Encryptor(config['password'],
                                            config['method'])
        if not self._encryptor:
            raise Exception('Encryptor initalize filed')

        self._local_sock.setblocking(False)
        self._local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT

        self.bindTCPTXNEvent(loop)

    def bindTCPTXNEvent(self,event_loop):
        if self._eventloop:
            raise Exception("bindTCPTXNEvent failed, already event loop")
        if self._stop:
            raise Exception("bindTCPTXNEvent failed, Tcp dispather is stopped")
        self._eventloop = event_loop
        self._eventloop.add(self._local_sock,eventloop.POLL_IN | eventloop.POLL_ERR, self._dispatcher)

    def handle_TCPTXN(self, sock, event):
        # handle all events in this handler and dispatch them to methods
        if self._stage == STAGE_DESTROYED:
            logging.debug('ignore handle_event: destroyed')
            return
        if sock == self._remote_sock:
            if event & eventloop.POLL_ERR:
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                self._on_local_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            logging.warn('unknown socket')

    def _update_stream(self, stream, status):
        # update a stream to a new waiting status

        # check if status is changed
        # only update if dirty
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if dirty:
            if self._local_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                if self._upstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                self._eventloop.modify(self._local_sock, event)
            if self._remote_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                if self._upstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                self._eventloop.modify(self._remote_sock, event)

    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]

      #  if self._forbidden_iplist:
      #      if common.to_str(sa[0]) in self._forbidden_iplist:
      #          raise Exception('IP %s is in forbidden list, reject' %common.to_str(sa[0]))

        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_handler_map[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock

    def _handle_dns_resolved(self, result, error):
        if error:
            self._log_error(error)
            self.destroy()
            return
        if result and result[1]:
            ip = result[1]
            try:
                self._stage = STAGE_CONNECTING
                remote_addr = ip
                remote_port = self._remote_address[1]
                logging.info('STAGE_DNS completed,remote_addr: %s,remote_port: %s' % (remote_addr, remote_port))

                remote_sock = self._create_remote_socket(remote_addr,remote_port)
                try:
                    remote_sock.connect((remote_addr, remote_port))
                except (OSError, IOError) as e:
                    if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                        pass
                self._eventloop.add(remote_sock,eventloop.POLL_ERR | eventloop.POLL_OUT,self._dispatcher)
                self._stage = STAGE_CONNECTING
                self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                return
            except Exception as e:
                shell.print_exception(e)
                if self._config['verbose']:
                    traceback.print_exc()
        self.destroy()

    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
        if not self._local_sock:
            return

        data = None
        try:
            data = self._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
      #  self._update_activity(len(data))
        data = self._encryptor.decrypt(data)
        if not data:
            return
        if self._stage == STAGE_STREAM:
            self._handle_stage_stream(data)
            return
        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data)
        elif self._stage == STAGE_INIT:
          #  logging.info('STAGE_INIT,_on_local_read: %s' % data)

            self._handle_stage_addr(data)

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_read(self):
        # handle all remote read events
        data = None
        try:
            data = self._remote_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        logging.info('STAGE_STREAM _on_remote_read, ip: %s, port: %s' % (self._remote_address[0], self._remote_address[1]))

        #self._update_activity(len(data))
        data = self._encryptor.encrypt(data)
        try:
            self._dispatcher.setTst(True)

            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _on_remote_write(self):
        # handle remote writable event
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
           # logging.info('STAGE_STREAM ,_on_remote_write: %s' % data)
            logging.info(
                'STAGE_STREAM _on_remote_write, ip: %s, port: %s' % (self._remote_address[0], self._remote_address[1]))
            self._write_to_sock(data, self._remote_sock)
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            logging.info('---clientStateStrem-------_on_remote_write _remote_sock event POLL_OUT no write data')

    def _handle_stage_addr(self, data):
        try:
            header_result = parse_header(data)
            if header_result is None:
                raise Exception('can not parse header')
            addrtype, remote_addr, remote_port, header_length = header_result
        #    logging.info('connecting %s:%d from %s:%d' %
         #                (common.to_str(remote_addr), remote_port,
         #                 self._client_address[0], self._client_address[1]))

            # spec https://shadowsocks.org/en/spec/one-time-auth.html
            if addrtype & ADDRTYPE_AUTH:
                if len(data) < header_length + ONETIMEAUTH_BYTES:
                    logging.warn('one time auth header is too short')
                    return None
                offset = header_length + ONETIMEAUTH_BYTES
                _hash = data[header_length: offset]
                _data = data[:header_length]
                key = self._encryptor.decipher_iv + self._encryptor.key
                if onetimeauth_verify(_hash, _data, key) is False:
                    logging.warn('one time auth fail')
                    self.destroy()
                header_length += ONETIMEAUTH_BYTES
            self._remote_address = (common.to_str(remote_addr), remote_port)
            # pause reading
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            self._stage = STAGE_DNS

            if len(data) > header_length:
                self._data_to_write_to_remote.append(data[header_length:])
            # notice here may go into _handle_dns_resolved directly
            self._dns_resolver.resolve(remote_addr,self._handle_dns_resolved)
        except Exception as e:
           # self._log_error(e)
            if self._config['verbose']:
                traceback.print_exc()
            self.destroy()

    def _handle_stage_connecting(self, data):
        self._data_to_write_to_remote.append(data)

    def _handle_stage_stream(self, data):
        self._write_to_sock(data, self._remote_sock)
        return

    def _write_to_sock(self, data, sock):
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
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
            if error_no in (errno.EAGAIN, errno.EINPROGRESS,errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock:unknown socket')
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                pass
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
                pass
            else:
                logging.error('write_all_to_sock:unknown socket')
        return True

    def _on_local_error(self):
        logging.debug('got local error')
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
        self.destroy()

    def _on_remote_error(self):
        logging.debug('got remote error')
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
        self.destroy()

    def destroy(self):
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.info('destroy: %s:%d' % self._remote_address)
        else:
            logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._eventloop.remove(self._remote_sock)
            del self._fd_handler_map[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._eventloop.remove(self._local_sock)
            del self._fd_handler_map[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        #self._dns_resolver.remove_callback(self._handle_dns_resolved)
        #self._server.remove_handler(self)
