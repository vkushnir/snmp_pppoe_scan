#!/usr/bin/python2
"""
    This python module is used for ISG services BiKaDa

    Written by : Vladimir Kushnir
    Created date: 22.11.2017
    Last modified: 22.11.2017
    Tested with : Python 2.7.14
"""
__version__ = '0.1'
__copyright__ = "Vladimir Kushnir aka Kvantum i(c)2017"

import sys, os
import pysnmp.smi
from pysnmp.hlapi import *
from optparse import OptionParser, OptionGroup
from pysnmp import debug

#debug.setLogger(debug.Debug('dsp', 'msgproc', 'secmod', 'mibbuild', 'mibview'))
#debug.setLogger(debug.Debug('mibbuild'))
#debug.setLogger(debug.Debug('msgproc', 'dsp', 'io', 'app'))


def get_param(arguments=None):
    """Parse Command-Line parameters"""
    parser = OptionParser(usage="%prog [options] [Server 01] [Server 02] [Server xx]", version="%prog " + __version__)
    parser.add_option('-d', action="store_true", dest='dupe', default=False,
                      help='shows only logins with duplicated MAC')
    parser.add_option('-o', action="store_true", dest='out', default=False,
                      help='shows snmp output')

    group = OptionGroup(parser, "SNMP")
    group.add_option('-v', dest='snmp_version', choices=['1', '2c', '3'], default='2c',
                     help="specifies SNMP version to use")
    group.add_option('-c', dest='snmp_community', default='public',
                     help='set the community string')
    group.add_option('-M', dest='snmp_dir', default='mibs',
                     help='look in given list of directories for MIBs')
    parser.add_option_group(group)

    (opt, args) = parser.parse_args(arguments)

    if opt.snmp_version == '3':
        parser.error("SNMP version 3 not supported yet !")
    if len(args) < 1:
        parser.error("You must specify at least one Server !")

    return args, opt


def snmp_get(snmp, auth, transport, context, obj):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(snmp, auth, transport, context, obj)
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
    return varBinds


def snmp_walk(snmp, auth, transport, context, obj, out=False):
    items = dict()
    for (errorIndication, errorStatus, errorIndex, varBinds) in \
            nextCmd(snmp, auth, transport, context, obj):
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for varBind in varBinds:
                if out:
                    print(' = '.join([x.prettyPrint() for x in varBind]))
                items[int(varBinds[0][0].getMibSymbol()[2][0])] = str(varBinds[0][1])
                #items.append(str(varBinds[0][1]))
    return items


def snmp_bulk(snmp, auth, transport, context, obj, out=False):
    items = dict()
    for (errorIndication, errorStatus, errorIndex, varBinds) in \
            bulkCmd(snmp, auth, transport, context, 0, 25, obj, lexicographicMode=False):
        if errorIndication:
            print(errorIndication)
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for varBind in varBinds:
                if out:
                    print(' = '.join([x.prettyPrint() for x in varBind]))
                items[int(varBinds[0][0].getMibSymbol()[2][0])] = str(varBinds[0][1])
                #items.append(str(varBinds[0][1]))
    return items


def scan_server(ip, options):
    """Scan given server and return tuple with [ user = MAC ] list"""
    print("Scan server", ip)
    snmp_engine = SnmpEngine()
    snmp_context = ContextData()
    mibBuilder = pysnmp.smi.builder.MibBuilder()
    mibSources = mibBuilder.getMibSources()
    #mibBuilder.setMibSources(*mibSources)
    mibBuilder.loadModules('CISCO-SUBSCRIBER-SESSION-MIB', 'CISCO-SUBSCRIBER-IDENTITY-TC-MIB')

    if options.snmp_version == '1':
        snmp_auth = CommunityData(options.snmp_community, mpModel=0)
    elif options.snmp_version == '2c':
        snmp_auth = CommunityData(options.snmp_community)
    else:
        print(options.snmp_version, "not implemented")
    snmp_transport = UdpTransportTarget((ip, 161))
    #csubSessionState, csubSessionCreationTime, csubSessionNativeIpAddr, csubSessionNasPort, csubSessionAcctSessionId, csubSessionLastChanged
    snmp_object = ObjectType(ObjectIdentity('CISCO-SUBSCRIBER-SESSION-MIB', 'csubSessionUsername')) \
        .addAsn1MibSource("file://"+os.path.abspath(options.snmp_dir))
    if options.snmp_version == '1':
        users = snmp_walk(snmp_engine, snmp_auth, snmp_transport, snmp_context, snmp_object, options.out)
    else:
        users = snmp_bulk(snmp_engine, snmp_auth, snmp_transport, snmp_context, snmp_object, options.out)
    print('Active users:', len(users))
    #return {user: ip for user in users}
    return users

    # snmp_object = ObjectType(ObjectIdentity('CISCO-SUBSCRIBER-SESSION-MIB', 'csubSessionMacAddress')) \
    #    .addAsn1MibSource("file://"+os.path.abspath(options.snmp_dir))
    #snmp_bulk(snmp_engine, snmp_auth, snmp_transport, snmp_context, snmp_object)


def get_dups(list):
    """Return all duplicated [ user ] entries from given list"""
    pass


def main(servers, options):
    def get_dup(items):
        match = items.pop(0)
        dup = [item for item in items if item[2] == match[2]]
        if len(dup) > 0:
            print dup
            new_items = [item for item in items if item[2] != match[2]]
        else:
            new_items = list(items)
        if len(new_items) > 1:
            get_dup(new_items)

    users = dict()
    for server in servers:
        users[server] = scan_server(server, options)
        items = [[ip, idx, users[ip][idx]] for ip in users.keys() for idx in users[ip].keys()]
    if options.dupe:
        while len(items) > 1:
            match = items.pop(0)
            dups = [item for item in items if item[2] == match[2]]
            if len(dups) > 0:
                dups.append(match)
                print dups
                items = [item for item in items if item[2] != match[2]]
    else:
        for item in items:
            print item


if __name__ == '__main__':
    srv, opt = get_param()
    if len(srv) >= 1:
        exit_status = int(not main(srv, opt))
    else:
        exit_status = 1
    sys.exit(exit_status)
