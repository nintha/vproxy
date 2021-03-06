package vpacket.conntrack.tcp;

import vfd.IPv4;
import vfd.IPv6;
import vpacket.AbstractIpPacket;
import vpacket.Ipv4Packet;
import vpacket.Ipv6Packet;
import vpacket.TcpPacket;
import vproxybase.util.ByteArray;
import vproxybase.util.Consts;

import java.util.Collections;

public class TcpUtils {
    private TcpUtils() {
    }

    public static TcpPacket buildCommonTcpResponse(TcpEntry tcp) {
        var ret = new TcpPacket();
        ret.setSrcPort(tcp.destination.getPort());
        ret.setDstPort(tcp.source.getPort());
        ret.setSeqNum(tcp.sendingQueue.getFetchSeq());
        ret.setAckNum(tcp.receivingQueue.getAckedSeq());
        ret.setWindow(tcp.receivingQueue.getWindow() / tcp.receivingQueue.getWindowScale());

        return ret;
    }

    public static AbstractIpPacket buildIpResponse(TcpEntry tcp, TcpPacket tcpPkt) {
        if (tcp.source.getAddress() instanceof IPv4) {
            var ipv4 = new Ipv4Packet();
            ipv4.setSrc((IPv4) tcp.destination.getAddress());
            ipv4.setDst((IPv4) tcp.source.getAddress());
            var tcpBytes = tcpPkt.buildIPv4TcpPacket(ipv4);

            ipv4.setVersion(4);
            ipv4.setIhl(5);
            ipv4.setTotalLength(20 + tcpBytes.length());
            ipv4.setTtl(64);
            ipv4.setProtocol(Consts.IP_PROTOCOL_TCP);
            ipv4.setOptions(ByteArray.allocate(0));

            ipv4.setPacket(tcpPkt);
            return ipv4;
        } else {
            var ipv6 = new Ipv6Packet();
            ipv6.setSrc((IPv6) tcp.destination.getAddress());
            ipv6.setDst((IPv6) tcp.source.getAddress());
            var tcpBytes = tcpPkt.buildIPv6TcpPacket(ipv6);

            ipv6.setVersion(6);
            ipv6.setNextHeader(Consts.IP_PROTOCOL_TCP);
            ipv6.setPayloadLength(tcpBytes.length());
            ipv6.setHopLimit(64);
            ipv6.setExtHeaders(Collections.emptyList());

            ipv6.setPacket(tcpPkt);
            return ipv6;
        }
    }

    public static TcpPacket buildAckResponse(TcpEntry tcp) {
        TcpPacket respondTcp = buildCommonTcpResponse(tcp);
        respondTcp.setFlags(Consts.TCP_FLAGS_ACK);
        return respondTcp;
    }

    public static TcpPacket buildRstResponse(TcpEntry tcp) {
        TcpPacket respondTcp = buildCommonTcpResponse(tcp);
        respondTcp.setFlags(Consts.TCP_FLAGS_RST);
        return respondTcp;
    }
}
