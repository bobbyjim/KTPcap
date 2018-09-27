package net.rje.pcap.builder;

import net.rje.pcap.api.Packet;
import net.rje.pcap.packet.UdpPacket;

import java.net.InetAddress;
import java.util.Date;

public class UdpPacketBuilder
{
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
        Packet udpPacket = new UdpPacket(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);
        return udpPacket;
    }
}
