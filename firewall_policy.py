#!/usr/bin/python

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import packets
from pyretic.core import packet

def make_firewall_policy(config):

    # You may place any user-defined functions in this space.
    # You are not required to use this space - it is available if needed.

    # feel free to remove the following "print config" line once you no longer need it
    # it will not affect the performance of the autograder
    print config

    # The rules list contains all of the individual rule entries.
    disallowedrules = []

    for entry in config:
        # "config" is a list that contains all of the entries that are parsed from firewall-config.pol file.
        # Each entry represents one line from the firewall-config.pol file.  The entry is a python dictionary that
        # contains each item defined in a single line from the firewall-config.pol file. The name of each
        # dictionary item is defined in firewall.py

        # Check protocol
        if (entry["protocol"] == "T"):
            rule = match(ethtype=packet.IPV4, protocol=packet.TCP_PROTO)
        elif (entry["protocol"] == "U"):
            rule = match(ethtype=packet.IPV4, protocol=packet.UDP_PROTO)
        elif (entry["protocol"] == "I"):
            rule = match(ethtype=packet.IPV4, protocol=packet.ICMP_PROTO)
        elif (entry["protocol"] == "O"):
            rule = match(ethtype=packet.IPV4, protocol=int(entry["ipproto"]))

        # Check source and destination MAC addresses
        if (entry["macaddr_src"] != "-"):
            rule = rule & match(srcmac=EthAddr(entry["macaddr_src"]))
        if (entry["macaddr_dst"] != "-"):
            rule = rule & match(dstmac=EthAddr(entry["macaddr_dst"]))

        # Check source and destination IP addresses
        if (entry["ipaddr_src"] != "-"):
            rule = rule & match(srcip = entry["ipaddr_src"])
        if (entry["ipaddr_dst"] != "-"):
            rule = rule & match(dstip = entry["ipaddr_dst"])

        # Check source and destination ports
        if (entry["port_src"] != "-"):
            rule = rule & match(srcport = int(entry["port_dst"]))
        if (entry["port_dst"] != "-"):
            rule = rule & match(dstport = int(entry["port_dst"]))

        # "Empty" rule: will block all IPv4 packets
        if (entry["protocol"] == "-" and entry["macaddr_src"] == "-" and entry["macaddr_dst"] == "-" and entry["ipaddr_src"] == "-" and entry["ipaddr_dst"] == "-" and entry["port_src"] == "-" and entry["port_dst"] == "-"):
            rule = match(ethtype=packet.IPV4)

        disallowedrules.append(rule)
        pass

    allowed = ~(union(disallowedrules))

    return allowed
