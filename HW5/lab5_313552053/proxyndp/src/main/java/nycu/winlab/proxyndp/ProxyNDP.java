/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.proxyndp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.ConnectPoint;

import org.onosproject.net.DeviceId;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import java.nio.ByteBuffer;
import java.util.Dictionary;
import java.util.Properties;

import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;

import java.util.HashMap;

import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.PortNumber;
import org.onlab.packet.ARP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           property = {
               "someProperty=Some Default String Value",
           })
public class ProxyNDP {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgeService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();

    private ApplicationId appId;
    private HashMap<Ip4Address, MacAddress> arpTable;
    private HashMap<Ip6Address, MacAddress> ndpTable;

    private HashMap<MacAddress, ConnectPoint> connectpointTable;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nycu.winlab.proxyndp");

        packetService.addProcessor(processor, PacketProcessor.director(1));

        // Request ARP packets
        TrafficSelector.Builder selectorArp = DefaultTrafficSelector.builder();
        selectorArp.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selectorArp.build(), PacketPriority.REACTIVE, appId);

        // Request IPv6 packets for NDP
        TrafficSelector.Builder selectorIpv6 = DefaultTrafficSelector.builder();
        selectorIpv6.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selectorIpv6.build(), PacketPriority.REACTIVE, appId);

        arpTable = new HashMap<Ip4Address, MacAddress>();
        ndpTable = new HashMap<Ip6Address, MacAddress>();
        connectpointTable = new HashMap<MacAddress, ConnectPoint>();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);

        // Cancel ARP packet requests
        TrafficSelector.Builder selectorArp = DefaultTrafficSelector.builder();
        selectorArp.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selectorArp.build(), PacketPriority.REACTIVE, appId);

        // Cancel IPv6 packet requests
        TrafficSelector.Builder selectorIpv6 = DefaultTrafficSelector.builder();
        selectorIpv6.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selectorIpv6.build(), PacketPriority.REACTIVE, appId);

        packetService.removeProcessor(processor);
        processor = null;

        arpTable = null;
        ndpTable = null;
        connectpointTable = null;

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");

    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            if (isControlPacket(ethPkt)) {
                return;
            }

            if (ethPkt.getDestinationMAC().isLldp()) {
                return;
            }

            MacAddress srcMac = ethPkt.getSourceMAC();

            // Handle ARP packets
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arpPayload = (ARP) ethPkt.getPayload();
                Ip4Address srcIP4Address = Ip4Address.valueOf(arpPayload.getSenderProtocolAddress());
                if (!arpTable.containsKey(srcIP4Address)) {
                    arpTable.put(srcIP4Address, srcMac);
                }

                if (!connectpointTable.containsKey(srcMac)) {
                    connectpointTable.put(srcMac, pkt.receivedFrom());
                }

                arpHandler(context);
                return;
            }

            // Handle IPv6 NDP packets
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();

                if (ipv6Packet.getNextHeader() == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();

                    if (icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_SOLICITATION ||
                        icmp6Packet.getIcmpType() == ICMP6.NEIGHBOR_ADVERTISEMENT) {

                        Ip6Address srcIP6Address = Ip6Address.valueOf(ipv6Packet.getSourceAddress());
                        if (!ndpTable.containsKey(srcIP6Address)) {
                            ndpTable.put(srcIP6Address, srcMac);
                        }

                        if (!connectpointTable.containsKey(srcMac)) {
                            connectpointTable.put(srcMac, pkt.receivedFrom());
                        }

                        ndpHandler(context);
                        return;
                    }
                }
            }
        }
    }

    private void arpHandler(PacketContext context) {

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        ARP arpPayload = (ARP) ethPkt.getPayload();
        Ip4Address dstIp4Address = Ip4Address.valueOf(arpPayload.getTargetProtocolAddress());
        short opCode = arpPayload.getOpCode();

        if (opCode == ARP.OP_REQUEST) {

            if (arpTable.containsKey(dstIp4Address)) {
                MacAddress dstMac = arpTable.get(dstIp4Address);
                Ethernet arpPacket = ARP.buildArpReply(dstIp4Address, dstMac, ethPkt);
                packetOut(pkt.receivedFrom().deviceId(), pkt.receivedFrom().port(),
                            ByteBuffer.wrap(arpPacket.serialize()));
                log.info("ARP TABLE HIT. Requested MAC = {}", dstMac);
            } else {
                for (ConnectPoint cp : edgeService.getEdgePoints()) {
                    if (!pkt.receivedFrom().deviceId().equals(cp.deviceId())
                            || !pkt.receivedFrom().port().equals(cp.port())) {
                        packetOut(cp.deviceId(), cp.port(),
                                ByteBuffer.wrap(ethPkt.serialize()));
                    }
                }

                log.info("ARP TABLE MISS. Send request to edge ports");
            }
        } else if (opCode == ARP.OP_REPLY) {
            MacAddress dstMac = MacAddress.valueOf(arpPayload.getTargetHardwareAddress());
            if (!connectpointTable.containsKey(dstMac)) {
                log.info("didn't find target host");
                return;
            }
            packetOut(connectpointTable.get(dstMac).deviceId(),
                    connectpointTable.get(dstMac).port(),
                    ByteBuffer.wrap(ethPkt.serialize()));
            log.info("RECV REPLY. Request MAC = {}",
                 MacAddress.valueOf(arpPayload.getSenderHardwareAddress()));
        }
    }

    private void ndpHandler(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv6 ipv6Packet = (IPv6) ethPkt.getPayload();
        ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();

        byte icmpType = icmp6Packet.getIcmpType();

        if (icmpType == ICMP6.NEIGHBOR_SOLICITATION) {
            NeighborSolicitation ns = (NeighborSolicitation) icmp6Packet.getPayload();
            Ip6Address targetIp6Address = Ip6Address.valueOf(ns.getTargetAddress());

            if (ndpTable.containsKey(targetIp6Address)) {
                // NDP Table Hit - send Neighbor Advertisement
                MacAddress targetMac = ndpTable.get(targetIp6Address);
                Ethernet ndpReply = buildNdpReply(ethPkt, ipv6Packet,
                        targetIp6Address, targetMac);

                packetOut(pkt.receivedFrom().deviceId(), pkt.receivedFrom().port(),
                         ByteBuffer.wrap(ndpReply.serialize()));
                log.info("NDP TABLE HIT. Requested MAC = {}", targetMac);
            } else {
                // NDP Table Miss - flood to edge ports
                for (ConnectPoint cp : edgeService.getEdgePoints()) {
                    if (!pkt.receivedFrom().deviceId().equals(cp.deviceId())
                            || !pkt.receivedFrom().port().equals(cp.port())) {
                        packetOut(cp.deviceId(), cp.port(),
                                ByteBuffer.wrap(ethPkt.serialize()));
                    }
                }
                log.info("NDP TABLE MISS. Send NDP Solicitation to edge ports");
            }
        } else if (icmpType == ICMP6.NEIGHBOR_ADVERTISEMENT) {
            // Handle Neighbor Advertisement - forward to the requesting host
            NeighborAdvertisement na = (NeighborAdvertisement) icmp6Packet.getPayload();
            Ip6Address targetIp6Address = Ip6Address.valueOf(na.getTargetAddress());

            // Extract target MAC from the original NS packet
            MacAddress dstMac = ethPkt.getDestinationMAC();

            if (connectpointTable.containsKey(dstMac)) {
                packetOut(connectpointTable.get(dstMac).deviceId(),
                         connectpointTable.get(dstMac).port(),
                         ByteBuffer.wrap(ethPkt.serialize()));
                log.info("RECV ADVERTISEMENT. Requested MAC = {}", ethPkt.getSourceMAC());
            }
        }
    }

    private Ethernet buildNdpReply(Ethernet ethRequest, IPv6 ipv6Request,
                                   Ip6Address targetIp, MacAddress targetMac) {
        // Build Neighbor Advertisement packet
        Ethernet ethReply = new Ethernet();
        ethReply.setEtherType(Ethernet.TYPE_IPV6);
        ethReply.setDestinationMACAddress(ethRequest.getSourceMAC());
        ethReply.setSourceMACAddress(targetMac);

        IPv6 ipv6Reply = new IPv6();
        ipv6Reply.setSourceAddress(targetIp.toOctets());
        ipv6Reply.setDestinationAddress(ipv6Request.getSourceAddress());
        ipv6Reply.setHopLimit((byte) 255);
        ipv6Reply.setNextHeader(IPv6.PROTOCOL_ICMP6);

        ICMP6 icmp6Reply = new ICMP6();
        icmp6Reply.setIcmpType(ICMP6.NEIGHBOR_ADVERTISEMENT);
        icmp6Reply.setIcmpCode((byte) 0);

        NeighborAdvertisement na = new NeighborAdvertisement();
        na.setTargetAddress(targetIp.toOctets());
        na.setSolicitedFlag((byte) 1);
        na.setOverrideFlag((byte) 1);

        // Add target link-layer address option
        na.addOption(NeighborDiscoveryOptions.TYPE_TARGET_LL_ADDRESS,
                    targetMac.toBytes());

        icmp6Reply.setPayload(na);
        ipv6Reply.setPayload(icmp6Reply);
        ethReply.setPayload(ipv6Reply);

        return ethReply;
    }

    private void packetOut(DeviceId targetDeviceId, PortNumber portNumber, ByteBuffer pktData) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(portNumber).build();
        OutboundPacket outboundPacket = new DefaultOutboundPacket(targetDeviceId, treatment, pktData);

        packetService.emit(outboundPacket);
    }

    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

}