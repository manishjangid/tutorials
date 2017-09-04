#Ipv6 config in mininet hosts

mininet> h1 sysctl -w net.ipv6.conf.h1-eth0.disable_ipv6=0   << Enable ipv6 only on h1-eth0 interface.

To enable ipv6 on all interfaces : h1 sysctl -w net.ipv6.conf.h1-eth0.disable_ipv6=0

mininet> h1 ifconfig h1-eth0 inet6 add 2001::3/96
mininet> ifconfig
*** Unknown command: ifconfig
mininet> h1 ifconfig
h1-eth0   Link encap:Ethernet  HWaddr 00:04:00:00:00:00 
          inet addr:10.0.0.10  Bcast:10.0.0.255  Mask:255.255.255.0
          inet6 addr: 2001::3/96 Scope:Global
          inet6 addr: fe80::204:ff:fe00:0/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:13 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:1142 (1.1 KB)

lo        Link encap:Local Loopback 
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

mininet>


Reason for it :

In p4_mininet.py file,

class P4Host(Host):
    def config(self, **params):
        r = super(P4Host, self).config(**params)

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (self.defaultIntf().name, off)
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

The following commands are disabling ipv6 on the hosts.

