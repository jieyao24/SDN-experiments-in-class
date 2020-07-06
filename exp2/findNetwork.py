from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER 
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu.topology.api import get_all_host, get_all_link, get_all_switch
from ryu.lib.packet import ether_types
import networkx as nx

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__

class NetworkAwareness(app_manager.RyuApp): 
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs): 
		super(NetworkAwareness, self).__init__(*args, **kwargs) 
		self.dpid_mac_port = {}
		self.topo_thread = hub.spawn(self._get_topology)
		self.mac_to_port={}
		self.sw={}
		self.graph = nx.DiGraph()

	def add_flow(self, datapath, priority, match, actions): 
		dp = datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
		dp.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
	def switch_features_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
		self.add_flow(dp, 0, match, actions)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# get Datapath ID to identify OpenFlow switches.
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		# analyse the received packets using the packet library.
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		if eth.ethertype == ether_types.ETH_TYPE_IPV6:
			return

		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		dst = eth_pkt.dst
		src = eth_pkt.src
		# add new host into the grpah
		if src_mac not in self.graph:
            self.graph.add_node(src_mac)
            self.graph.add_edge(src_mac, dpid)
            self.graph.add_edge(dpid, src_mac, port=in_port)

		# get the received port number from packet_in message.
		in_port = msg.match['in_port']
		header_list = dict((p.protocol_name, p)for p in pkt.protocols if type(p) != str)
		# self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# if the destination mac address is already learned,
		# decide which port to output the packet, otherwise FLOOD.
		if ETHERNET in header_list:
			eth_dst = header_list[ETHERNET].dst
			eth_src = header_list[ETHERNET].src
		if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
			arp_dst_ip = header_list[ARP].dst_ip
			if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
				if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
					out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=datapath.ofproto.OFP_NO_BUFFER,in_port=in_port,actions=[], data=None)
					datapath.send_msg(out)
					return
			else:
				self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port
		# learn a mac address to avoid FLOOD next time.
		#self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
			#self.logger.info(out_port)
		else:
			if dst_mac in self.graph:
                if dst_mac not in self.paths[src_mac]:
                    try:
                        path = nx.shortest_path(self.graph, src_mac, dst_mac, weight=None)
                        self.paths[src_mac][dst_mac] = path
                        print('path:', path)
                    except:
                        return
                path = self.paths[src_mac][dst_mac]
                next_hop = path[path.index(dpid)+1]
                out_port = self.graph[dpid][next_hop]['port']
                self.mac_to_port[dpid][dst_mac] = out_port

		# construct action list.
		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time.
		
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			self.add_flow(datapath, 1, match, actions)
	
		# construct packet_out message and send it.
		out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=in_port, actions=actions,data=msg.data)
		datapath.send_msg(out)

	def _get_topology(self): 
		hub.sleep(10)
		self.logger.info('\n\n\n')
		#hosts = get_all_host(self) 
		switches = get_all_switch(self) 
		links = get_all_link(self)

		self.logger.info('switches:') 
		for switch in switches:
			self.logger.info(switch.to_dict())
			#self.logger.info(switch)
			self.graph.add_node(switch.dp.id)

		self.logger.info('links:')
		for link in links:
			self.logger.info(link.to_dict()) 
			#self.logger.info('src='+str(link.src.dpid)+', dst='+str(link.dst.dpid))
			self.graph.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)
            self.graph.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no)