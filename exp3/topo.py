from mininet.topo import Topo
'''
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Node
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections
'''

class Mytopo(Topo):
    def __init__(self):
        super(Mytopo, self).__init__()
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
    

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s1, s4)
        self.addLink(s2, s3)
        self.addLink(s4, s5)
        self.addLink(s3, s5)
        self.addLink(s5, h2)

topos = { 'mytopo': (lambda : Mytopo())}
