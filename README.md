# Software-Defined Network-Based Firewall

This project aims to use software-defined networking (SDN) to create an externally configurable blacklist firewall using the SDN platform <a href="http://frenetic-lang.org/pyretic/">Pyretic</a> and the <a href="https://github.com/noxrepo/pox">POX OpenFlow Controller</a>.

The firewall rules are in the configuration file `firewall-config.pol`. The firewall policy is implemented in `firewall_policy.py`. The following rules are implemented:
- Block PPTP, prohibiting all hosts from sending traffic to a PPTP server running on `server2`.
- Prohibit all hosts from sending traffic to an SSH server on hosts `e1`, `e2`, and `e3`.
- Protect the DNS and NTP services on `server1` and `server2` from receiving traffic from all hosts.
- Disallow hosts `w1` and `w2` from pinging `client1`.
- Disallow host `e1` from sending traffic destined to TCP ports 9950-9952 on host `e3`.
- Restrict host `client1` from sending traffic to hosts `e1`, `e2`, and `e3`.
- Prohibit all hosts from sending traffic to a L2TP/IPSEC server running on `server3`. 


`firewall.py` sets up the Pyretic application and reads the firewall config into a data object. `firewall-topo.py` is a <a href="http://mininet.org/">Mininet</a> program that starts a topology consisting of one switch and two groups of hosts. The learning switch is implemented in `pyretic_switch.py`. `run-firewall.sh` is used to run the firewall; it also allows for different config files to be used by providing a filename via the command line.

For TCP testing: `test-tcp-client.py` acts as a TCP client - it opens a connection, sends a string, then waits to hear it echoed back. `test-tcp-server.py` acts as a TCP server - it listens on a specified port and echoes back whatever it hears.

For UDP testing: `test-udp-client.py` acts as a UDP client. `test-udp-server.py` acts as a UDP server that echoes back whatever it hears.
