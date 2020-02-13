#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

import os
import select
import subprocess
import errno
from vyatta.platform.basesfphelper import BaseSfpHelper
from vyatta.platform.basesfphelper import BusNotSupportedException
from vyatta.platform.basesfphelper import ModuleNotPresentException

class AcctonAS5916_54XKSSfpHelper(BaseSfpHelper):
    QSFP_EEPROM_TX_DISABLE_MASK = 0x0F
    QSFP_EEPROM_TX_ENABLE_MASK = 0x00
    QSFP_MAX_PORT = 6
    SFP_MAX_PORT = 48

    _ACCTON_IPMI_NETFN = 0x34
    _ACCTON_IPMI_QSFP_READ_CMD = 0x10
    _ACCTON_IPMI_QSFP_WRITE_CMD = 0x11
    _ACCTON_IPMI_SFP_READ_CMD = 0x1c
    _ACCTON_IPMI_SFP_WRITE_CMD = 0x1d

    def __init__(self, sfpd):
        self.sfp_plugged = dict.fromkeys(range(self.SFP_MAX_PORT), False)
        self.qsfp_plugged = dict.fromkeys(range(self.QSFP_MAX_PORT), False)
        self.sfpd = sfpd

    def _send_bmc_ipmi_message(self, cmd, data):
        # No suitable python3-compatible library could be found to do this
        # natively so execute ipmitool
        args = ["/usr/bin/ipmitool", "raw", str(self._ACCTON_IPMI_NETFN),
                str(cmd)]
        # Turn list of bytes into string representation
        args += [str(b) for b in data]
        resp = subprocess.run(args, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,
                              universal_newlines=True).stdout
        # Turn response into list of integers to represent the bytes
        return [int(x, base=16) for x in resp.split()]

    class SfpBus():
        def __init__(self, parent, port):
            self.p = parent
            self.port = port

        def read_word_data(self, addr, cmd):
            reqdata = [ self.port + 1, addr ]
            try:
                data = self.p._send_bmc_ipmi_message(
                    self.p._ACCTON_IPMI_SFP_READ_CMD, reqdata)
            except subprocess.CalledProcessError:
                raise OSError(errno.ENXIO, "address not found")
            return int.from_bytes(bytes(data[cmd * 2 : cmd * 2 + 2]),
                                  byteorder='big')

        def write_word_data(self, addr, cmd, val):
            reqdata = [ self.port + 1, addr, 1 ]
            reqdata += [ cmd ]
            reqdata += val.to_bytes(2, byteorder='big')
            try:
                self.p._send_bmc_ipmi_message(
                    self.p._ACCTON_IPMI_SFP_WRITE_CMD, reqdata)
            except subprocess.CalledProcessError:
                raise OSError(errno.ENXIO, "address not found")

    class SfpBusResource():
        def __init__(self, parent, port):
            self.parent = parent
            self.port = port

        def __enter__(self):
            return self.parent.SfpBus(self.parent, self.port)

        def __exit__(self, *args):
            # Nothing to do
            pass

    def get_bus(self, porttype, port):
        if porttype == 'SFP':
            return self.SfpBusResource(self, port)
        elif porttype == 'QSFP':
            raise BusNotSupportedException('Port of type ' + porttype + ' doesn\'t support embedded PHYs')
        else:
            raise Exception("unexpected port type {}".format(porttype))

    def set_sfp_state(self, portname, enabled):
        if portname.startswith('xe'):
            port = int(portname[2:])
            reqdata = [ port + 1, 0x01, 1 if enabled else 0 ]
            self._send_bmc_ipmi_message(self._ACCTON_IPMI_SFP_WRITE_CMD,
                                        reqdata)
        elif portname.startswith('ce'):
            # Attempt to extract the sub-port index if broken out.
            # Note: the sub-port number is 0-based.
            subportparts = portname[2:].split('p', 1)
            port = int(subportparts[0])
            subport = None
            if len(subportparts) > 1:
                subport = int(subportparts[1])

            if subport is None:
                if enabled:
                    mask = self.QSFP_EEPROM_TX_ENABLE_MASK
                else:
                    mask = self.QSFP_EEPROM_TX_DISABLE_MASK
            else:
                reqdata = [ 0x01 ]
                port_disable_masks = self._send_bmc_ipmi_message(
                    self._ACCTON_IPMI_QSFP_READ_CMD, reqdata)

                mask = port_disable_masks[port]
                if enabled:
                    mask &= ~(1 << subport)
                else:
                    mask |= (1 << subport)

            reqdata = [ port + 1, 0x01, mask ]
            try:
                self._send_bmc_ipmi_message(
                    self._ACCTON_IPMI_QSFP_WRITE_CMD, reqdata)
            except subprocess.CalledProcessError:
                raise ModuleNotPresentException('ce' + str(port))
        else:
            raise Exception("unexpected port type {}".format(portname))

    def query_eeprom(self, porttype, port):
        if porttype == 'SFP':
            pages = [ 0xa0 ]

            # Try to get first 128 bytes of page a2
            reqdata = [ port + 1, 2 ]
            try:
                self._send_bmc_ipmi_message(self._ACCTON_IPMI_SFP_READ_CMD,
                                            reqdata)
                pages.append(0xa2)
            except subprocess.CalledProcessError:
                pass

            return pages
        elif porttype == 'QSFP':
            pages = []
            for page in range(4):
                # Assume that pages 00h - 03h are present
                pages.append(page)
            return pages
        else:
            raise Exception("unexpected port type {}".format(porttype))

    def read_eeprom(self, porttype, port, offset=None, length=None):
        cmd = self._ACCTON_IPMI_SFP_READ_CMD
        portname = None
        if offset is None:
            offset = 0
        if porttype == 'SFP':
            portname = 'xe' + str(port)
            if length is None:
                length = 512
        elif porttype == 'QSFP':
            cmd = self._ACCTON_IPMI_QSFP_READ_CMD
            portname = 'ce' + str(port)
            if length is None:
                length = 128 + 4 * 128
        else:
            raise Exception("unexpected port type {}".format(porttype))

        data = []
        for page in range((offset // 128) * 128, offset + length, 128):
            reqdata = [ port + 1, page // 128 ]
            try:
                data += self._send_bmc_ipmi_message(cmd, reqdata)
            except subprocess.CalledProcessError:
                raise ModuleNotPresentException(portname + ' page ' + str(page // 128) + ' not available')
        data = data[offset % 128:offset % 128 + length]
        return bytes(data)

    def _get_all_sfp_presence(self):
        reqdata = [ 0x10 ]
        return self._send_bmc_ipmi_message(
            self._ACCTON_IPMI_SFP_READ_CMD, reqdata)

    def _get_all_qsfp_presence(self):
        reqdata = [ 0x10 ]
        return self._send_bmc_ipmi_message(
            self._ACCTON_IPMI_QSFP_READ_CMD, reqdata)

    def _walk_ports(self):
        sfp_ports_presence = self._get_all_sfp_presence()
        for port in range(self.SFP_MAX_PORT):
            presence = sfp_ports_presence[port]
            if presence != self.sfp_plugged[port]:
                self.sfp_plugged[port] = presence
                self.sfpd.on_sfp_presence_change('xe' + str(port),
                                                 'SFP', port, presence)
        qsfp_ports_presence = self._get_all_qsfp_presence()
        for port in range(self.QSFP_MAX_PORT):
            presence = qsfp_ports_presence[port]
            if presence != self.qsfp_plugged[port]:
                self.qsfp_plugged[port] = presence
                self.sfpd.on_sfp_presence_change('ce' + str(port),
                                                 'QSFP', port, presence)

    def main_loop(self, file_evmask_tuple_list):
        p = select.poll()

        for (f, evmask) in file_evmask_tuple_list:
            p.register(f, evmask)

        # gather state at boot
        self._walk_ports()

        while True:
            evtuple_list = p.poll(1000)
            if len(evtuple_list) == 0:
                self._walk_ports()
            for (fd, event) in evtuple_list:
                self.sfpd.on_file_event(fd, event)

def new_helper(sfpd):
    return AcctonAS5916_54XKSSfpHelper(sfpd)
