package net.rje.pcap.packet;

import net.rje.pcap.api.Packet;

import java.net.InetAddress;
import java.util.Date;

public class UdpPacket extends IpPacket implements Packet
{
    public UdpPacket(    long timestamp,
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
