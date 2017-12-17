using System;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.AirPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;

namespace MySniffer
{
    /// <summary>
    /// Custom Udp sniffer. Usage:
    /// 1. Select device
    /// 2. Call MySniffer.SetDeviceAndPort(device, port, eventHandler)
    /// 3. device.StartCapture() --> Calls input eventHandler whenever UDP data at input port is received.
    /// </summary>
    public class Sniff
    {
        private static event Action<UdpPacketReceivedArgs> UdpPacketReceived;
        private static ushort _destinationPort = 443;

        /// <summary>
        /// Dummy method for standalone test.
        /// </summary>
        /// <param name="args"></param>
        internal static void OnDataReceived(UdpPacketReceivedArgs args)
        {
            Console.WriteLine("\n--- UDP data received ---");
            Console.WriteLine("sourcePort: " + args.SourcePort + ", destinationPort: " + args.DestinationPort);
            Console.WriteLine("payloadData: " + Encoding.ASCII.GetString(args.PayloadData));
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("SharpPcap {0}", SharpPcap.Version.VersionString);
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------\n");
            var iDevice = 0;
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", iDevice, dev.Name, dev.Description);
                iDevice++;
            }
            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            var iSelection = int.Parse(Console.ReadLine());
            var device = devices[iSelection];
            Console.Write("-- Please enter port: ");
            var port = ushort.Parse(Console.ReadLine());
            SetDeviceAndPort(device, port, OnDataReceived);
            Console.WriteLine("-- Listening on {0} {1}...", device.Name, device.Description);
            Console.WriteLine("-- Press enter to stop.");
            device.StartCapture();
            //device.Capture(); // Infinite, code does not go below this line.
            Console.ReadLine(); // Wait for 'Enter' from the user.
            device.StopCapture();
            Console.WriteLine("-- Capture stopped.");
            Console.WriteLine(device.Statistics.ToString());
            device.Close();
            Console.ReadLine(); // Wait for 'Enter' from the user.
        }

        public static void SetDeviceAndPort(ICaptureDevice device, ushort port, Action<UdpPacketReceivedArgs> udpPacketReceived)
        {
            UdpPacketReceived += udpPacketReceived;
            _destinationPort = port;
            device.OnPacketArrival += OnPacketArrival;
            // Open the device for capturing
            device.Open();
            const int readTimeoutMilliseconds = 1000;
            if (device is AirPcapDevice)
            {
                // NOTE: AirPcap devices cannot disable local capture
                Console.WriteLine("device is AirPcapDevice");
                var airPcap = (AirPcapDevice) device;
                airPcap.Open(OpenFlags.DataTransferUdp, readTimeoutMilliseconds);
            }
            else if (device is WinPcapDevice)
            {
                Console.WriteLine("device is WinPcapDevice");
                var winPcap = (WinPcapDevice) device;
                winPcap.Open(OpenFlags.DataTransferUdp | OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);
            }
            else if (device is LibPcapLiveDevice)
            {
                Console.WriteLine("device is LibPcapLiveDevice");
                var livePcapDevice = (LibPcapLiveDevice) device;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                throw new InvalidOperationException("unknown device type of " + device.GetType());
            }
        }

        /// <summary>
        /// Prints UPD packets received at input destination port.
        /// </summary>
        private static void OnPacketArrival(object sender, CaptureEventArgs e)
        {
            //Console.WriteLine("e.Packet.LinkLayerType: " + e.Packet.LinkLayerType);
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            if (!(packet is EthernetPacket)) return;
            var ip = (IpPacket)packet.Extract(typeof(IpPacket));
            if (ip == null) return;
            var udp = (UdpPacket)packet.Extract(typeof(UdpPacket));
            if (udp == null || udp.DestinationPort != _destinationPort) return;
            Console.WriteLine("UDP:");
            Console.WriteLine("source port: " + udp.SourcePort + ", dest port: " + udp.DestinationPort);
            Console.WriteLine("data: " + Encoding.ASCII.GetString(e.Packet.Data));
            Console.WriteLine("PayloadData: " + Encoding.ASCII.GetString(udp.PayloadData));
            UdpPacketReceived?.Invoke(new UdpPacketReceivedArgs(udp.PayloadData, udp.SourcePort, udp.DestinationPort));
            /*var time = e.Packet.Timeval.Date;
            var len = e.Packet.PayloadData.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}", 
                time.Hour, time.Minute, time.Second, time.Millisecond, len);
            Console.WriteLine(e.Packet.ToString());*/
        }
    }

    public class UdpPacketReceivedArgs : EventArgs
    {
        public byte[] PayloadData { get; }
        public ushort SourcePort { get; }
        public ushort DestinationPort { get; }

        public UdpPacketReceivedArgs(byte[] payloadData, ushort sourcePort, ushort destinationPort)
        {
            PayloadData = payloadData;
            SourcePort = sourcePort;
            DestinationPort = destinationPort;
        }
    }
}
