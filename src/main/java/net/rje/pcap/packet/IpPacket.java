package net.rje.pcap.packet;

import net.rje.pcap.api.Packet;

import java.net.InetAddress;
import java.util.Date;

public class IpPacket implements Packet
{
    private long timestamp;
    private Date date;
    private long packetSize;
    private boolean isLoopback;
    private int etherHeaderLength;
    private InetAddress sourceAddress;
    private InetAddress destinationAddress;
    private byte[] payload;
    private byte[] data;

    public IpPacket(long timestamp,
                    Date date,
                    long packetSize,
                    boolean isLoopback,
                    int etherHeaderLength,
                    InetAddress sourceAddress,
                    InetAddress destinationAddress,
                    byte[] payload,
                    byte[] data )
    {
        this.timestamp = timestamp;
        this.date = date;
        this.packetSize = packetSize;
        this.isLoopback = isLoopback;
        this.etherHeaderLength = etherHeaderLength;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.payload = payload;
        this.data = data; // the whole packet
    }

    public long getTimestamp() { return timestamp; }
    public long getPacketSize() { return packetSize; }

    public boolean isLoopback() {
        return isLoopback;
    }

    public int getEtherHeaderLength() { return etherHeaderLength; }
    public InetAddress getSourceAddress() { return sourceAddress; }
    public InetAddress getDestinationAddress() { return destinationAddress; }
    public byte[] getData() { return data; }

    public int getIpHeaderLength()
    {
        return (data[etherHeaderLength] & 0xf) * 4;
    }
}
