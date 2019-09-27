#! /usr/bin/python
# -*- coding: iso-8859-1 -*-
'''
    module name: iplist2forti.py
    purpose    : convert list of IP addresses into 
                 1- a FORTINET batch commandfile
                 and
                 2- a 'purge' commandfile to remove the entries again
                 
                 create address definitions, address groups
                 and supergroup to use in one or more policies
                 numeric IPs or FQDNs allowed
                 uses sockets for resolving FQDNs
                 recognizes hosts.deny file syntax as input file
    required   : python 2.7 or higher
    created    : 2010-07-18
    last change: 2015-12-01

    Copyright by E/S/P Dr. Beneicke, Heidelberg (http://beneicke-edv.de/support/tools)
'''

import sys
import argparse
import socket   # for nslookup()


# globals
DEBUG = False

# ----------------
# FortiOS specific strings
# object names used in FortiOS
AddrName = 'zblock{0:04d}'
DummyName = 'block_dummy'
DummyIP = '169.254.254.254'
AddrGrpName = 'blockgroup{0:03d}'
SuperGrpName = 'sblockgroups{0:03d}'

cmdAddr_start = 'config firewall address\n'
cmdAddr       = '  edit {0:s}\n    set subnet {1:s}/32\n  next\n'
cmdDelete     = '  delete {0:s}\n'

cmdAddrGrp_start = 'config firewall addrgrp\n'
cmdAddrGrp       = '  edit {0:s}\n    set member'.format(AddrGrpName)
cmdSuperGrp      = '  edit {0:s}\n    set member'
cmdNoSuperGrp    = '  edit {0:s}\n    set member {1:s}'.format(SuperGrpName, DummyName)
cmdEnd = 'end\n\n'
cmdNext = '\n  next\n'
cmdNextEnd = '\n  next\nend\n\n'

# hard limits for all models
maxgroups = 2500       # number of address groups
maxgroupsize = 300     # addresses per group
modeldata = {          # max # of addresses, desired_groupsize <= maxgroupsize
    's': (2500, 20),
    'm': (10000, 100),
    'l': (40000, 300)
}

# ----------------


def createDatedFile(fname, mode='w', withminutes=False):
    '''
    Open a file for writing.
    Creates missing path components if necessary.
    Default mode suits text files; use 'wb' for binary access.
    Filename will be 'fname' + current date.
    if withminutes, hour and minute will be included in name.
    Existing file will be overwritten.
    '''
    import os.path
    import sys
    import time

    err = sys.stderr.write    # alias

    create = 'w' in mode or 'a' in mode
    if create:
        path, filename = os.path.split(fname)
        if path:
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except IOError, msg:
                    err('createDatedfile()/makedirs(%s):\n%s\n' % (path, msg))
                    return None

    # construct filename
    tmstamp = time.strftime("_%Y-%m-%d")
    if withminutes:
        tmstamp = time.strftime("_%Y-%m-%d_%H%M")
    filename = filename_insert(fname, tmstamp)
    # now open the file
    try:
        f = open(filename, mode)
    except IOError, msg:
        err('createDatedFile(%s):\n%s\n' % (filename, msg))
        return None
    else:
        return f


def nslookup(fqdn):
    try:
        IP = socket.gethostbyname(fqdn)
    except socket.error:
        if DEBUG:
            print('\t\tcannot resolve "' + fqdn + '"')
        IP = None
    return(IP)


def filename_insert(fname, insert):
    import os.path

    filename, ext = os.path.splitext(fname)
    return ''.join((filename, insert, ext))


def isNumericIPaddress(ip):
    # returns TRUE if <ip> string is a valid numeric IPv4 address
    if ip.count('.') == 3 and ip.replace('.', '').isdigit():
        for part in ip.split('.'):
            if not (0 <= int(part) <= 255):
                return False
        return True
    return False


def isFQDN(ip):
    ''' returns TRUE if <ip> string could be a FQDN
        needs at least one dot and last part is non-numeric
    '''
    return (ip.count('.') > 1) and not (ip.split('.')[-1].isdigit())


def readIPlist(fd):
    '''
    read all lines from open file handle fd
    ignore comment lines starting with '#' or empty lines
    return list of strings
    recognizes alternative host.deny file format

    sample:
    # bla bla
    1.34.163.57
    2.86.93.35
    2.93.72.124

    or
    # /etc/hosts.deny
    # See "man tcpd" and "man 5 hosts_access" as well as /etc/hosts.allow
    # for a detailed description.

    http-rman : ALL EXCEPT LOCAL

    # DenyHosts: Sun May  2 09:38:19 2010 | sshd: 221.11.70.139
    sshd: 221.11.70.139
    # DenyHosts: Sun May  2 17:26:29 2010 | sshd: 85.17.155.134
    sshd: 85.17.155.134
    '''

    isHostDenyFile = False
    IPlist = []
    for line in fd:
        ip = line.strip()
        if not ip or ip.startswith('#'):
            # try to recognize host.deny file from first comment
            if not isHostDenyFile and '/etc/hosts.deny' in ip:
               isHostDenyFile = True
            continue
        if isHostDenyFile:
            if ip.count(':') == 1:
                ip = ip.split(':')[1].strip()

        if ip.count('.') > 0:  # rough check
            IPlist.append(ip)
    fd.close()
    return IPlist


def checkRawIPs(rawIPs, topN, dontResolve):
    '''
    returns a list of numeric IP addresses
    FQDNs are either resolved or skipped
    '''
    global DEBUG

    # start with the most recent entry first
    # in case only the first TopN entries are used
    rawIPs.reverse()

    IPs = []
    uniqueIPs = set([])  # used for check only
    for ip in rawIPs:   # may be an IP or an FQDN
        if len(IPs) >= topN:
            break
        if not isNumericIPaddress(ip):
            host = ip
            ip = ''
            if not dontResolve and isFQDN(host):
                ip = nslookup(host)
                if DEBUG and ip:
                    print('{0:55s} is {1:>17s}'.format(host, ip))
            if not ip:
                continue
        if not ip in uniqueIPs:
            IPs.append(ip)
            uniqueIPs.add(ip)
    return IPs


def grpnum(i):
    global groupsize

    # map item #i to group number containing groupsize items
    # group number: 0..
    return (i // groupsize)


def purgecmd(first, last, splitcount):
    '''
    returns delete commands for IP #<first> to #<last>

    delete groups but not the group of groups (SuperGrp)
    because it's used in the DENY policy
    delete all address groups from SuperGrp by inserting
    one dummy address only
    split addresses evenly into splitcount supergroups
    '''

    cmd = []
    add = cmd.append      # an alias

    # create dummy address entry if not existent
    add(cmdAddr_start)
    add(cmdAddr.format(DummyName, DummyIP))
    add(cmdEnd)

    group1 = grpnum(first)
    groupN = grpnum(last)
    ngroups = groupN - group1 + 1
    # create/edit super group(s), referenced in DENY policy/policies
    add(cmdAddrGrp_start)
    for isplit in range(splitcount):
        add(cmdNoSuperGrp.format(isplit))
        add(cmdNext)
    add(cmdEnd)

    add(cmdAddrGrp_start)
    for g in range(group1, groupN + 1):
        add(cmdDelete.format(AddrGrpName.format(g)))
    add(cmdEnd)

    # delete addresses
    add(cmdAddr_start)
    for i in range(first, last + 1):
        add(cmdDelete.format(AddrName.format(i)))
    add(cmdEnd)

    return(''.join(cmd))  # list to string


def main():
    global DEBUG, groupsize

    # ----------------
    # parse command line args
    p = argparse.ArgumentParser(description='Create (a lot of) address \
    objects and groups from list for use in FortiOS.')

    p.set_defaults(                  \
        model = 'm',                 \
        maxAddr = 999999,            \
        prevAddr = 0,                \
        dontresolve = False,         \
        debug = False,               \
        cmdfname = 'blocklist.bcmd', \
        splitcount = 1
    )

    addarg = p.add_argument    # an alias

    addarg('-m', '--model', action='store', dest='model',
           nargs=1, choices='sml',
           help='FortiGate model: small (<FGT-100) / medium (<FGT-1000) / large')
    addarg('-n', '--newest', action='store', dest='maxAddr',
           type=int,
           help='use only newest/last <%(dest)s> addresses from list')
    addarg('-p', '--prev', action='store', dest='prevAddr', type=int,
           help='replace <%(dest)s> old addresses')
    addarg('-d', '--dontresolve', action='store_true', dest='dontresolve',
           help='skip non-numeric addresses (FQDNs) in input')
    addarg('-D', '--debug', action='store_true', dest='debug',
           help='print debug output')
    addarg('infile', type=argparse.FileType('r', 0),
           help='read IPs from <%(dest)s>')
    addarg('-o', '--outfile', dest='cmdfname',
           help='write output to <%(dest)s>')
    addarg('-s', '--split', action='store', dest='splitcount',
           type=int,
           help='split output into <%(dest)s> parts')

    args = p.parse_args()

    # ----------------
    # get and set parameters
    model = args.model[0].lower()
    maxAddr = min(modeldata[model][0], args.maxAddr)

    purgefn = filename_insert(args.cmdfname, '_purge')
    DEBUG = args.debug

    if args.prevAddr is None:
        ans = raw_input('How many OLD addresses are currently defined? [0..] ')
        try:
            args.prevAddr = int(ans)
        except TypeError, ValueError:
            print('Invalid input.')
            sys.exit(-1)
        print('')

    splitcount = args.splitcount

    # ----------------
    # write bulk command files
    # one for defining, one for purging

    cmdfile = createDatedFile(args.cmdfname, 'w', True)
    if not cmdfile:
        sys.exit(-1)
    out = cmdfile.write       # just an alias

    # ----------------
    # read IPs from file
    rawIPs = readIPlist(args.infile)
    nRaw = len(rawIPs)
    # ----------------
    # check and resolve the IPs
    maxAddr = min(nRaw, maxAddr)
    IPs = checkRawIPs(rawIPs, maxAddr, args.dontresolve)
    ipcount = len(IPs)
    skipped = nRaw - ipcount
    # ----------------
    # report to user
    print('\n')
    print('bulk commandfile created: {0:s}'.format(cmdfile.name))
    print('specific for {0:s} Fortigate model'.format({'s': 'small', 'm': 'medium', 'l': 'large'}[model]))
    print('{0:5d} IPs in file'.format(ipcount + skipped))
    if skipped:
        print('{0:5d} IP{1:s} skipped'.format(skipped, '' if skipped == 1 else 's'))
    if ipcount == 0:
       sys.exit(0)
    # ----------------

    # def group size: max(desired_groupsize, ipcount/maxgroups) <= size < maxgroupsize
    desired_groupsize = modeldata[model][1]
    groupsize = max(desired_groupsize, ipcount // maxgroups)
    groupsize = min(groupsize, maxgroupsize)

    # ----------------
    # first, delete old definitions to free up memory
    # delete only if there are more old addresses than new ones
    first = ipcount
    last = args.prevAddr
    delprev = ''
    if first < last:
        delprev = 'deleted old addresses {0:d} to {1:d}'.format(first, last)
        cmd = purgecmd(first, last-1, splitcount)  # from# .. to# ..
        out(cmd)

    # create all new address objects
    out(cmdAddr_start)
    for i in range(ipcount):
        out(cmdAddr.format(AddrName.format(i), IPs[i]))
    out(cmdEnd)

    # add address groups with max. groupsize addresses each
    ngroups = -(-ipcount / groupsize)  # == ceil()
    out(cmdAddrGrp_start)
    # group#, address# 0..
    for g in range(ngroups):
        out(cmdAddrGrp.format(g))
        for a in range(groupsize):
            out(' ' + AddrName.format(g * groupsize + a))   # add address to group
        out(cmdNext)

    # create/edit super group(s), referenced in DENY policy/policies
    supergroupsize = -(-ngroups / splitcount)  # == ceil()
    isplit = 0
    for g in range(ngroups):
        if (g % supergroupsize) == 0:
            if g > 0:
                out(cmdNext)
            out(cmdSuperGrp.format(SuperGrpName.format(isplit)))
            isplit += 1
        # add address groups to super group
        out(' ' + AddrGrpName.format(g))

    out(cmdNextEnd)

    # ----------------
    # write a purgefile to be able to delete all definitions created here
    with createDatedFile(purgefn, 'w', True) as purgefile:
        cmd = purgecmd(0, ipcount-1, splitcount)    # from# .. to# inclusive
        purgefile.write(cmd)
        purgefn = purgefile.name

    # ----------------
    print('{0:5d} IPs in {1:d} address group{2:s} of size {3:d}'.format(
        ipcount,
        ngroups,
        '' if ngroups == 1 else 's',
        groupsize)
    )
    print('{0:5d} address groups in {1:d} super group{2:s} of size {3:d}'.format(
        ngroups,
        splitcount,
        '' if splitcount == 1 else 's',
        supergroupsize)
    )
    if delprev:
        print delprev

    print('\n')
    print('apply bulk command file ' + cmdfile.name)
    print('refer to address group "{0:s}" in DENY policy'.format(SuperGrpName.format(0)))
    print('to get rid of these addresses, apply ' + purgefn)


if __name__ == '__main__':
    main()
