package net.rje.pcap.api;

import java.net.InetAddress;

public interface Packet
{
     long getTimestamp();
     long getPacketSize();

     boolean isLoopback();
     int getEtherHeaderLength();
     InetAddress getSourceAddress();
     InetAddress getDestinationAddress();
     byte[] getData();

     int getIpHeaderLength();
}
