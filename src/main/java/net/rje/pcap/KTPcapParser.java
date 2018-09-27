package net.rje.pcap;

import net.rje.pcap.api.Packet;
import net.rje.pcap.builder.IpPacketBuilder;
import sun.misc.IOUtils;

import java.io.*;

public class KTPcapParser
{
    public static final int globalHeaderLength = 24;

    IpPacketBuilder builder;

    public KTPcapParser(FileInputStream is) throws IOException
    {
        builder = getBuilder(is);
    }

    public Packet getPacket()
    {
        return builder.readPacket();
    }

    public static IpPacketBuilder getBuilder(FileInputStream is) throws IOException
    {
        // Read global header
        byte[] globalHeader = IOUtils.readNBytes(is,globalHeaderLength);
        if ( notPcap(globalHeader) )
            return null;

        //  Return a generic packet reader/builder
        return new IpPacketBuilder(is);
    }

    private static boolean notPcap(byte[] data)
    {
        return data[0] != -44      // D4
                || data[1] != -61  // C3
                || data[2] != -78  // B2
                || data[3] != -95; // A1
    }

    public static void main(String[] args) throws IOException
    {
        File file = new File("c:\\Users\\eagro02\\Development\\git\\KTPcap\\src\\resources\\net.rje.pcap\\pcap-qhq3hyo5yecx.pcap");
        FileInputStream fis = new FileInputStream(file);
        KTPcapParser parser = new KTPcapParser(fis);

        int c = 0;
        for( Packet p = parser.getPacket(); p != null && p.getPacketSize() > -1; p = parser.getPacket() )
        {
            p.getIpHeaderLength(); // anything for the loop
            System.out.println( "Packet " + c + ": " + p.getPacketSize() + " bytes");
            c++;
        }
    }
}