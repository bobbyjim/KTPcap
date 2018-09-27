package net.rje.pcap.builder;

import net.rje.pcap.NumericUtils;
import net.rje.pcap.api.Packet;
import net.rje.pcap.packet.ErrorPackets;
import net.rje.pcap.packet.IpPacket;
import sun.misc.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;

public class IpPacketBuilder
{
    public static final int TCP = 6;
    public static final int UDP = 17;
    public static final int sourceAddressOffset = 12;
    public static final int destinationAddressOffset = sourceAddressOffset + 4;
    public static final int pcapHeaderLength = 16;
    public static final int packetLengthOffset = 8;


    public long timestamp;
    public Date date;
    public long packetSize;

    public InputStream in;

    public IpPacketBuilder(InputStream in) throws IOException
    {
        this.in = in;
    }

    public Packet readPacket() // throws IOException
    {
        // Read PCAP Header
        byte[] pcapHeader = null;
        try
        {
            pcapHeader = IOUtils.readNBytes(in, pcapHeaderLength);
        }
        catch( IOException ioe ) // EOF
        {
            return ErrorPackets.EOF;
        }

        long timestamp = fetchTimestamp(pcapHeader[0], pcapHeader[1], pcapHeader[2], pcapHeader[3]);

        Date date = new Date(timestamp);

        long packetSize = NumericUtils.toLong(pcapHeader[packetLengthOffset+3],
                pcapHeader[packetLengthOffset+2],
                pcapHeader[packetLengthOffset+1],
                pcapHeader[packetLengthOffset]);

        this.timestamp = timestamp;
        this.date = date;
        this.packetSize = packetSize;

        // Read Packet Data
        byte[] data = null;
        try {
            data = IOUtils.readNBytes(in, (int) packetSize);
        }
        catch( IOException ioe )
        {
            return ErrorPackets.ERROR;
        }

        boolean isLoopback = isLoopback(data[0], data[1], data[2], data[3]);
        int etherHeaderLength = getEtherHeaderLength(isLoopback);

        // Figure out the source and dest IP addresses
        InetAddress sourceAddress = getInetAddress(data, etherHeaderLength, sourceAddressOffset);
        InetAddress destinationAddress = getInetAddress(data, etherHeaderLength, destinationAddressOffset);

        // Figure out where the protocol data starts
        int ipHeaderLength = getIpHeaderLength(data, etherHeaderLength);
        int protocolDataOffset = etherHeaderLength + ipHeaderLength;

        // Get the payload
        byte[] payload = new byte[data.length - protocolDataOffset];
        System.arraycopy(data, protocolDataOffset, payload, 0, payload.length);

        // Figure out the protocol and call subordinate builders.
        int protocolOffset = etherHeaderLength + 9;
        if ( data[protocolOffset] == TCP )
            return TcpPacketBuilder.build(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);

        if ( data[protocolOffset] == UDP )
            return UdpPacketBuilder.build(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);

        return new IpPacket(timestamp, date, packetSize, isLoopback, etherHeaderLength, sourceAddress, destinationAddress, payload, data);
    }

    // Check for loopback and adjust header if necessary
    private int getEtherHeaderLength(boolean isLoopback)
    {
        return isLoopback? 4 : 14;
    }

    private long fetchTimestamp( byte a0, byte a1, byte a2, byte a3)
    {
        return    NumericUtils.toLong(a3, a2, a1, a0) * 1000; // seconds since 1970-01-01 00:00:00 UTC
    }

    private boolean isLoopback(byte a, byte b, byte c, byte d)
    {
        return     a == 2  // 2 = null.family is IP
                && b == 0  //
                && c == 0  //  null MAC address == loopback
                && d == 0; //
    }

    private InetAddress getInetAddress(byte[] data, int etherOffset, int ipSourceOffset)
    {
        int offset = etherOffset + ipSourceOffset;

        InetAddress addr = null;
        byte[] ip = new byte[4];
        System.arraycopy(data, offset, ip, 0, ip.length);
        try
        {
            addr = InetAddress.getByAddress(ip);
        }
        catch( UnknownHostException uhe )
        {
            uhe.printStackTrace();
        }
        return addr;
    }

    public int getIpHeaderLength(byte[] data, int etherHeaderLength)
    {
        return (data[etherHeaderLength] & 0xf) * 4;
    }
}
