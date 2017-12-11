using System;
using System.IO;
using System.Runtime.InteropServices;

namespace libpcap_reader
{
    class Program
    {
        static void Main(string[] args)
        {
            string inputFile = @"test.pcap";
            using (BinaryReader PcapFile = new BinaryReader(File.Open(inputFile, FileMode.Open, FileAccess.Read)))
            {
                // Read libpcap Global Header.
                GlobalHeader pcapHeader = (GlobalHeader)GetObjectFromBytes(PcapFile.ReadBytes(24), typeof(GlobalHeader));

                // Read Packets
                int packetNo = 0;
                int offset = 24;
                while (offset < PcapFile.BaseStream.Length)
                {
                    packetNo++;

                    PacketHeader packetHeader = (PacketHeader)GetObjectFromBytes(PcapFile.ReadBytes(16), typeof(PacketHeader));

                    int packetLength = (int)packetHeader.incl_len;
                    byte[] packet = PcapFile.ReadBytes(packetLength);
                    offset += 16 + packetLength;
                }

                Console.WriteLine(packetNo + " packets read..");
                Console.WriteLine("Complete.");
                Console.ReadKey();
            }
        }

        // https://stackoverflow.com/questions/6335153/casting-a-byte-array-to-a-managed-structure/6335855#6335855
        public static object GetObjectFromBytes(byte[] buffer, Type objType)
        {
            object obj = null;
            if ((buffer != null) && (buffer.Length > 0))
            {
                IntPtr ptrObj = IntPtr.Zero;
                try
                {
                    int objSize = Marshal.SizeOf(objType);
                    if (objSize > 0)
                    {
                        if (buffer.Length < objSize)
                            throw new Exception(String.Format("Buffer smaller than needed for creation of object of type {0}", objType));
                        ptrObj = Marshal.AllocHGlobal(objSize);
                        if (ptrObj != IntPtr.Zero)
                        {
                            Marshal.Copy(buffer, 0, ptrObj, objSize);
                            obj = Marshal.PtrToStructure(ptrObj, objType);
                        }
                        else
                            throw new Exception(String.Format("Couldn't allocate memory to create object of type {0}", objType));
                    }
                }
                finally
                {
                    if (ptrObj != IntPtr.Zero)
                        Marshal.FreeHGlobal(ptrObj);
                }
            }
            return obj;
        }

        // Libpcap File Format:  https://wiki.wireshark.org/Development/LibpcapFileFormat
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct GlobalHeader
        {
            public UInt32 magic_number;
            public UInt16 version_major;
            public UInt16 version_minor;
            public Int32 thiszone;
            public UInt32 sigfigs;
            public UInt32 snaplen;
            public UInt16 network;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct PacketHeader
        {
            public UInt32 ts_sec;
            public UInt32 ts_usec;
            public UInt32 incl_len;
            public UInt32 orig_len;
        }
    }
}
