package net.rje.pcap;

public class NumericUtils
{
    public static long toLong(byte hi1, byte hi2, byte lo1, byte lo2)
    {
        return ((hi1 & 0xff) << 24)
                | ((hi2 & 0xff) << 16)
                | ((lo1 & 0xff) << 8)
                | ((lo2 & 0xff));
    }

    public static int toShort(byte hi, byte lo)
    {
        return ((hi & 0xff) << 8)
                | (lo & 0xff);
    }
}
