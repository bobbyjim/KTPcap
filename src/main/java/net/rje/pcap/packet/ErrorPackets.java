package net.rje.pcap.packet;

import net.rje.pcap.api.Packet;

import java.net.InetAddress;

public enum ErrorPackets implements Packet
{
    EOF,
    ERROR;

    public long getTimestamp() { return -1; }
    public long getPacketSize() { return -1; }

    public boolean isLoopback() { return false; }
    public int getEtherHeaderLength() { return -1; }
    public InetAddress getSourceAddress() { return null; }
    public InetAddress getDestinationAddress() { return null; }
    public byte[] getData() { return null; }

    public int getIpHeaderLength() { return -1; }
}
