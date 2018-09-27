package net.rje.pcap.builder;

import net.rje.pcap.api.Packet;
import net.rje.pcap.packet.TcpPacket;
import net.rje.pcap.NumericUtils;

import java.net.InetAddress;
import java.util.Date;

public class TcpPacketBuilder
{
    public static final int tcpHeaderDataOffset = 12;

    public static Packet build(long timestamp,
                            Date date,
                            long packetSize,
                            boolean isLoopback,
                            int etherHeaderLength,
                            InetAddress sourceAddress,
                            InetAddress destinationAddress,
                            byte[] payload,
                            byte[] data)
    {

        TcpPacket tcpPacket = new TcpPacket(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);

        int sourcePortOffset = etherHeaderLength + tcpPacket.getIpHeaderLength();
        tcpPacket.sourcePort = NumericUtils.toShort(data[sourcePortOffset], data[sourcePortOffset+1]);

        int destinationPortOffset = sourcePortOffset + 2;
        tcpPacket.destinationPort = NumericUtils.toShort(data[destinationPortOffset], data[destinationPortOffset+1]);

        return tcpPacket;
    }

    public int getTcpHeaderLength(byte[] data, Packet packet)
    {
        int offset = tcpHeaderDataOffset + packet.getEtherHeaderLength() + packet.getIpHeaderLength();
        return ((data[offset] >> 4) % 0xf) * 4;
    }
}
