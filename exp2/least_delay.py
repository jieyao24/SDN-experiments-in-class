from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.topology.api import get_all_link, get_all_switch
from ryu.base.app_manager import lookup_service_brick
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time


ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__

class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        # mapping (dpid, mac) and in_port 
        self.mac_to_port = {} 
        # mapping (dpid, mac, dst_ip) and in_port in order to deal with the circle problem 
        self.sw = {}
        self.switches = None
        self.paths = {}
        self.lldp_delay = {}
        self.echo_delay = {}
        self.topo_thread = hub.spawn(self.get_topology_delay)
        self.graph = nx.DiGraph()
        self.topology_api_app = self

    def add_flow(self, datapath, priority, match, actions):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        data = "%.6f" % time.time()
        echo_req = parser.OFPEchoRequest(dp, data=data)
        dp.send_msg(echo_req)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            try:
                src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
                if self.switches is None:
                    self.switches = lookup_service_brick('switches')
                for port in self.switches.ports.keys():
                    if src_dpid == port.dpid and src_port_no == port.port_no:
                        self.lldp_delay[(src_dpid, dpid)] = self.switches.ports[port].delay
            except:
                return
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        if src_mac not in self.graph:
            self.graph.add_node(src_mac)
            self.graph.add_edge(src_mac, dpid, weight=0)
            self.graph.add_edge(dpid, src_mac, weight=0, port=in_port)

        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)

        if dst_mac == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (dpid, src_mac, arp_dst_ip) in self.sw:
                if self.sw[(dpid, src_mac, arp_dst_ip)] != in_port: 
                    out = parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], 
                        data=None
                    )
                    dp.send_msg(out)
                    return
            else:
                self.sw[(dpid, src_mac, arp_dst_ip)] = in_port

        # mac learning
        self.mac_to_port.setdefault(dpid, {})
        self.paths.setdefault(src_mac, {})

        out_port = ofp.OFPP_FLOOD

        if dst_mac in self.mac_to_port[dpid]: 
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            if dst_mac in self.graph:
                if dst_mac not in self.paths[src_mac]:
                    try:
                        path = nx.shortest_path(self.graph, src_mac, dst_mac, weight="weight")
                        self.paths[src_mac][dst_mac] = path
                        print ('path:',path)
                    except:
                        return
                path = self.paths[src_mac][dst_mac]
                next_hop = path[path.index(dpid)+1]
                out_port = self.graph[dpid][next_hop]['port']
                self.mac_to_port[dpid][dst_mac] = out_port

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(dp, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        dp.send_msg(out) 

    def get_topology_delay(self):

        hub.sleep(2)

        switch_list = get_all_switch(self)
        switches = [switch.dp.id for switch in switch_list]
        self.graph.add_nodes_from(switches)

        # get edges
        link_list = get_all_link(self)
        for link in link_list:
            try:
                lldp_delay1 = self.lldp_delay[(link.src.dpid, link.dst.dpid)]
                lldp_delay2 = self.lldp_delay[(link.dst.dpid, link.src.dpid)]
                echo_delay1 = self.echo_delay[link.src.dpid]
                echo_delay2 = self.echo_delay[link.dst.dpid]
                delay = (lldp_delay1 + lldp_delay2 - echo_delay1 - echo_delay2) / 2
                w = max(delay, 0)
            except:
                w = float('inf')
            self.logger.info('lldp_delay: %s %s echo_delay: %s %s', lldp_delay1, lldp_delay2, echo_delay1, echo_delay2)
            self.logger.info('delay between %s and %s = %s ms', link.src.dpid, link.dst.dpid, delay * 1000)
            self.graph.add_edge(link.src.dpid, link.dst.dpid, weight=w, port=link.src.port_no)
            self.graph.add_edge(link.dst.dpid, link.src.dpid, weight=w, port=link.dst.port_no)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        recv_time = time.time()
        msg = ev.msg
        dpid = msg.datapath.id
        try:
            delay = recv_time - eval(msg.data)
            self.echo_delay[dpid] = delay
        except:
            return