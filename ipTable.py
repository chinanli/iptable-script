#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ipTable.py -s 10.82.112 10.82.113
#   A script that checks for mounted filesystems from “EOL” addresses, and
#   if they exist create a Network Address Translation rule to change the
#   destination IP to new address.
#
#   iptables -t nat -A OUTPUT -d <EOL IP ADDRESS> -j DNAT --to-destination <NEW IP ADDRESS>
#
#   To check applied nat rules use
#     iptables -t nat -–list
#
#   To clear applied nat rules use
#     iptables -t nat -–flush
#
# Author: Kerry Liu <chinan.liu@intel.com>
#
# Repository: https://gitlab.devtools.intel.com/chinanli/iptable-script.git
#
# Versions:
#   1.0 - Initial version  5/30/2022
#

import re
import os
import nis
import sys
import shlex
import socket
import argparse
import subprocess

VERBOSE = False
IPTABLES_BIN = '/usr/sbin/iptables'

def get_ip_from_nis(mounted_path, site_code, mounted_ip_address, nfs_device):
    """Get new IP address from NIS for the mounted path

    Parameters
    ----------
    path : str
        Path of the mounted filesystem
    eczone : str
        Site code of this system from /etc/automap.cf
    old_ip_address : str
        IP address of the fileserver network interface mounted at path
    device  : str
        The full nfs device mounted at path  fileserver:/fspath

    Returns
    -------
    str
        The IP of a fileserver found in NIS that matches the cluster and fspath
    """

    device_hostname, device_junction = nfs_device.split(':')

    # check if device fileserver matches the automap value fileserver.
    if device_hostname == mounted_ip_address:
        device_hostname = socket.gethostbyaddr(mounted_ip_address)[0].split('.')[0]

    # convert the path to something that we can lookup in nis
    if mounted_path.startswith('/nfs/'):
        if VERBOSE:
            print("site in path", mounted_path)
        # need to rewrite path to replace 'site' with eczone
        pathlist = mounted_path.split('/')
        pathlist[2] = site_code
        mounted_path = '/'.join(pathlist)

    pathlist = mounted_path.split('/')
    print(pathlist[2])
    automap = "automap.{0}".format(pathlist[2])
    print(automap)
    values = ''
    try:
        values = nis.match(mounted_path, automap).split()
    except:
        print(sys.exc_info()[0], "occured. Modify code: Look up automap-p_sc_#.<nfs/site>.")

    if VERBOSE:
        print(automap, mounted_path, values)

    cluster_name = device_hostname.split('n')[0] #scc25
    new_ip = ''
    # loop through all the nis devices
    for value in values:
        if not value.startswith('-'): #if its an option, remove it
            lif, junction = value.split(':')

            if lif == junction.split('/')[1]: # for /stod3015 its a vserver, there is no 'n' to split
                new_ip = socket.gethostbyname(lif)
                return new_ip

            elif junction == device_junction and lif.split('n')[0] == cluster_name:
                new_ip = socket.gethostbyname(lif) # the new ip addr
                if VERBOSE:
                    print("Junction and cluster match", junction,
                           device_junction, lif.split('n')[0], cluster_name)
                    print("New IP address found in {0}".format(pathlist[2]), new_ip)
                if new_ip == mounted_ip_address:
                    raise SystemExit("NIS needs to be updated with new Lif for {0} {1} {2}"
                                     .format(new_ip, mounted_path, values))
                else:
                    return new_ip
            elif site_code != 'sc':
                if VERBOSE:
                    print("The IP address cannot be found in {0}, searching in SC now.".format(pathlist[2]))
                return(get_ip_from_nis(mounted_path, 'sc', mounted_ip_address, nfs_device))
            else:
                print("IP address cannot be found")


'''
scc351159:~# iptables -t nat --list
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
DNAT       all  --  anywhere             sccfs07n07b-1.sc.intel.com  to:10.116.52.36

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination   
'''

def get_nat_rules():
    """Get defined DNAT rules from output of `/usr/sbin/iptables -t nat --list`
    Returns
    -------
    dict
        Dictionary of Network Addressable Translations
        { 'old-fully qualified hostname': 'new network interface IP address'}
    """

    defined_nat_rules = {}
# add lsmod & insmod here
    #rules_output = subprocess.check_output([IPTABLES_BIN, '-t', 'nat', '--list'],
    #                            shell=False).decode('utf-8')

    rules_output = subprocess.Popen([IPTABLES_BIN, '-t', 'nat', '--list'],
                                    shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    nat_rules = rules_output.stdout.readlines()
    rule = ''
    for rule_line in nat_rules:
        rule = rule_line.rstrip()

    found_Chain_OUTPUT = False

    for rule in nat_rules:
        if rule.startswith('Chain POSTROUNTING'):
            print("found chain POSTROUNTING")
            found_Chain_OUTPUT = False
        if rule.startswith('Chain OUTPUT'):
            found_Chain_OUTPUT = True
            print("found_Chain_OUTPUT")
            if rule.startswith('DNAT') and found_Chain_OUTPUT == True:
                print("Found the rule starts with DNAT", rule)
                if VERBOSE:
                    print("Rule:", rule)
                rule_definition = rule.split()
                print(rule_definition)
                if rule_definition[4] != 'anywhere' and rule_definition[5].startswith('to'):
                    if rule_definition[4] in defined_nat_rules:
                        print("duplicate rule found")
                    else:
                        defined_nat_rules[rule_definition[4]] = rule_definition[5].split(':')[1]
        

    return defined_nat_rules


if __name__ == '__main__':

    PARSER = argparse.ArgumentParser()
    PARSER.add_argument('-v', '--verbose', default=False, const=True, action='store_const')
    PARSER.add_argument('-e', '--execute', help='Execute commands', default=False, const=True
                        , action='store_const')
    PARSER.add_argument('-s', '--subnets', help='EOL Subnets', nargs='*')
    ARGS = vars(PARSER.parse_args())

    NAT_RULES = {}

    VERBOSE = ARGS['verbose']

    if os.path.exists(IPTABLES_BIN) == False and os.path.exists('/sbin/iptables') == True:
        IPTABLES_BIN = '/sbin/iptables'

    if os.geteuid() == 0:
        NAT_RULES = get_nat_rules()
        # return defined_nat_rules -> {'sccfs07n07b-1.sc.intel.com':'10.116.52.36'}

    EOL_SUBNETS = ARGS['subnets']

    # get the site code from the automap configuration file
    SITE = ''
    AUTOMAP_CF_FILE = open('/etc/automap.cf', "r")
    AUTOMAP_CF = AUTOMAP_CF_FILE.readlines()
    AUTOMAP_CF_FILE.close()
    for line in AUTOMAP_CF:
        if line.startswith('SITE='):
            SITE = line.strip().split('=')[-1]
            if VERBOSE:
                print(SITE)
    if SITE == '':
        raise SystemExit("site: {0} not found".format(SITE))
        #sys.exit()

    MOUNT_FILE = open('/proc/mounts', "r")
    MOUNTS = MOUNT_FILE.readlines()
    MOUNT_FILE.close()
    rule_count = 0
    mounted_eol_ip_addresses = NAT_RULES
    for mount in MOUNTS:
        ip_address = ''
        subnet = ''
        device, mount_point, mount_type, options, dump, fsck = mount.strip().split()
        if mount_type == 'nfs':
            for option in options.split(','):
                if option.startswith('addr='):
                    ip_address = option.split('=')[1]
                    subnet = '.'.join(ip_address.split('.')[0:-1])
            if subnet in EOL_SUBNETS:
                if ip_address not in mounted_eol_ip_addresses:
                    if VERBOSE:
                        print ("found in /proc/mounts: ", mount_point, ip_address)
                    mounted_eol_ip_addresses[ip_address] = 1

                    new_ip_address = get_ip_from_nis(mount_point, SITE, ip_address, device)

                    if new_ip_address == '':
                        continue

                    fqhn = socket.gethostbyaddr(ip_address)[0]
                    if VERBOSE:
                        print(fqhn)
                else:
                    if VERBOSE:
                        print("This IP address has been assigned")
                    continue

#                if new_ip_address == ip_address:
#                 raise SystemExit("NIS needs to be updated with new Lif for {} {} {}"
#                                     .format(new_ip_address, mount_point, ))
                    #sys.exit()


                # fqhn = fully qualified hostname
                if fqhn not in NAT_RULES:
                    rule_count += 1
                    if ARGS['execute']:
                        #result = subprocess.check_output([IPTABLES_BIN, '-t' , 'nat' , '-A' , 'OUTPUT' , '-d'
                        #                        , ip_address , '-j' , 'DNAT' , '--to-destination'
                        #                       , new_ip_address], shell=False).decode()

                        result = subprocess.Popen([IPTABLES_BIN, '-t' , 'nat' , '-A' , 'OUTPUT' , '-d'
                                                  , ip_address , '-j' , 'DNAT' , '--to-destination'
                                                  , new_ip_address], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        rule_count -= 1

                        NAT_RULES = get_nat_rules() # if user put -e, run the command, then update NAT_RULES
                        if VERBOSE:
                            print(NAT_RULES) # print the nat_rules
                    else:
                        print("iptables -t nat -A OUTPUT -d {0} -j DNAT --to-destination {1}"
                              .format(ip_address, new_ip_address))

                else:
                    if VERBOSE:
                        print('Rules for {} hostname is already defined: {0}'
                                     .format(fqhn, NAT_RULES))
    if rule_count == 0:
        #print(os.environ['HOSTNAME'], end=': ')
        print("All rules applied")

    else:
        print("Not all rules applied")

# Line 205 Checks:
# After everything is run and rules set, maybe check to make sure that for all mounts there are rules print the status

# read the existing nat tables, 
#if there are no mounts with mounted address in subnet list, then check the natrules and /proc/mounts, and check if subnets are mounted, if not mounted and there are rule, then remove the rules 
# func for clear the rules


#in execute mode,
#1. check nat rules
#2. 
# refer line 14
# ... print removing rules

# check is source in the table already? for example, the 113.134 repeats twice. if 134 already there, do not make another command.

# scymve020:~# iptables -t nat -A OUTPUT -d 10.82.113.134 -j DNAT --to-destination 10.116.52.40
# scymve020:~# iptables -t nat -A OUTPUT -d 10.82.113.134 -j DNAT --to-destination 10.116.52.39

#before iptable list
# check the kernal moduels (lsmod | grep nf_nat) 
# if doesn't exist, then insert the moduel int othe kernal 
# > insmod nf_nat          -> need to become root

'''
special case:
scyweb01:~# iptables -t nat --list
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
DNAT       tcp  --  anywhere             10.82.195.32         tcp dpt:http to:10.82.195.32:8080

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
DNAT       all  --  anywhere             scc09n02b-1.sc.intel.com  to:10.148.246.35

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination         


skip until Chain OUTPUT
Then find DNAT
'''

