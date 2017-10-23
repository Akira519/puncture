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
import logging
import stateControl
import shell
import daemon

def aa():
    shell.check_python()
    config = shell.get_config(False)
    daemon.daemon_exec(config)

    abc=eventloop.Eventloop()
    tcpsrv = stateControl.ServerStateControl(config,abc)
    tcpsrv.Pump()
if __name__ == '__main__':
    aa();