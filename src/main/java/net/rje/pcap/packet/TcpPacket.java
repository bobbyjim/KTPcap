package net.rje.pcap.packet;

import net.rje.pcap.api.Packet;

import java.net.InetAddress;
import java.util.Date;

public class TcpPacket extends IpPacket implements Packet
{
    public int sourcePort;
    public int destinationPort;

    public TcpPacket(    long timestamp,
                         Date date,
                         long packetSize,
                         boolean isLoopback,
                         int etherHeaderLength,
                         InetAddress sourceAddress,
                         InetAddress destinationAddress,
                         byte[] payload,
                         byte[] data )
    {
        super(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);
    }
}
