using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinDnsApi.NET.Private
{
    public static class DnsManagement
    {
        /// <summary>
        /// DNS Record Types (a subset).
        /// See: https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants
        /// </summary>
        public enum DnsRecordType : ushort
        {
            A = 0x0001,
            NS = 0x0002,
            CNAME = 0x0005,
            SOA = 0x0006,
            PTR = 0x000c,
            MX = 0x000f,
            TXT = 0x0010,
            AAAA = 0x001c,
            SRV = 0x0021,
            ANY = 0x00ff
        }

        // A-record data (4 bytes IPv4 address)
        [StructLayout(LayoutKind.Sequential)]
        public struct DNS_A_DATA
        {
            public uint IpAddress; // IPv4 in network order (little-endian on x86/x64)
        }

        /// <summary>
        /// Represents the "data" union part of a DNS_RECORD.
        /// We use Explicit layout to mimic the C union.
        /// </summary>
        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct DnsData
        {
            [FieldOffset(0)]
            public DNS_A_DATA A;
        }

        /// <summary>
        /// DNS Update Options for DnsModifyRecordsInSet_W.
        /// See: https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsmodifyrecordsinset_w
        /// </summary>
        [Flags]
        public enum DnsOptions : uint
        {
            /// <summary>
            /// Appends (adds) the DNS record if it does not exist.
            /// </summary>
            DNS_UPDATE_APPEND = 0x00000001,

            /// <summary>
            /// Removes the DNS record.
            /// </summary>
            DNS_UPDATE_REMOVE = 0x00000002,

            /// <summary>
            /// Replaces the DNS record.
            /// </summary>
            DNS_UPDATE_REPLACE = 0x00000004,

            /// <summary>
            /// Reserved, do not use.
            /// </summary>
            DNS_UPDATE_RESERVED = 0x00000008,

            /// <summary>
            /// Forces secure updates (TSIG).
            /// </summary>
            DNS_UPDATE_SECURITY_ON = 0x00000010,

            /// <summary>
            /// Forces non-secure updates.
            /// </summary>
            DNS_UPDATE_SECURITY_OFF = 0x00000020
        }

        [Flags]
        public enum DnsRecordFlags : uint
        {
            DnsRecordFlagUnused = 0,
            DnsRecordFlagDelete = 0x1,
            DnsRecordFlagExisting = 0x2
            // ... and many more
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
        public struct DnsRecord
        {
            public IntPtr pNext; // Pointer to the next DnsRecord (NULL to terminate)
            public IntPtr pszName;
            public DnsRecordType wType;
            public ushort wDataLength; // Not used for new records, calculated by the API.
            public DnsRecordFlags Flags;
            public uint dwTtl;
            public uint dwReserved;

            // This is the start of the C union (DnsRecordData)
            public DnsData Data;
        }

        public class DnsQueryResult
        {
            public int status;
            public List<string> records = new();
        }

        /// <summary>
        /// Corrected P/Invoke for DnsModifyRecordsInSet_W.
        /// Signature: DNS_STATUS WINAPI DnsModifyRecordsInSet_W(
        ///   _In_opt_  PDNS_RECORD  pAddRecords,
        ///   _In_opt_  PDNS_RECORD  pDeleteRecords,
        ///   _In_      DNS_UPDATE_OPTIONS  Options,
        ///   _In_opt_  HANDLE  hCredentials,
        ///   _In_opt_  PSOCKADDR_ARRAY  SockAddrArray,
        ///   _Reserved_  PVOID  pReserved
        /// );
        /// </summary>
        [DllImport("dnsapi.dll", EntryPoint = "DnsModifyRecordsInSet_W", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        public static extern int DnsModifyRecordsInSet(
             [In] IntPtr pAddRecords,
             [In] IntPtr pDeleteRecords,
             [In] DnsOptions options,
             [In] IntPtr hCredentials,
             [In] IntPtr sockAddrArray,
             [In] IntPtr pReserved);

        /// <summary>
        /// Creates a new A (Host) record in a DNS zone.
        /// </summary>
        /// <param name="zoneName">The name of the zone (e.g., "contoso.com").</param>
        /// <param name="recordName">The name of the host (e.g., "www" or "@" for the zone root).</param>
        /// <param name="ipAddress">The IPv4 address string (e.g., "192.168.1.100").</param>
        /// <param name="ttl">The Time-To-Live (TTL) for the record in seconds.</param>
        public static DnsQueryResult AddARecord(string recordName, string ipAddress, uint ttl)
        {
            DnsQueryResult result = new();

            // 1. Validate and parse the IP Address
            if (!IPAddress.TryParse(ipAddress, out IPAddress ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Invalid IPv4 address provided.", nameof(ipAddress));
            }

            // GetAddressBytes() returns in network order (big-endian)
            byte[] ipBytes = ip.GetAddressBytes();
            uint ipUint = BitConverter.ToUInt32(ipBytes, 0);

            IntPtr pRecordName = IntPtr.Zero;
            IntPtr pAddRecord = IntPtr.Zero;

            try
            {
                // CRITICAL: Manually allocate and marshal the string for pszName
                pRecordName = Marshal.StringToCoTaskMemUni(recordName);

                // 2. Create the DnsRecord struct in managed code
                var record = new DnsManagement.DnsRecord
                {
                    pszName = pRecordName, // Use the manually allocated pointer
                    wType = DnsManagement.DnsRecordType.A,
                    dwTtl = ttl,
                    Flags = 0,
                    pNext = IntPtr.Zero, // Null-terminate the linked list (only one record)
                    Data = new DnsManagement.DnsData
                    {
                        A = new DnsManagement.DNS_A_DATA
                        {
                            IpAddress = ipUint
                        }
                    }
                };
                // Set wDataLength for the A record data (which is 4 bytes)
                record.wDataLength = (ushort)Marshal.SizeOf(typeof(DnsManagement.DNS_A_DATA));


                // 3. Allocate unmanaged memory for the struct and marshal it
                pAddRecord = Marshal.AllocHGlobal(Marshal.SizeOf(record));
                Marshal.StructureToPtr(record, pAddRecord, false);

                // 4. Call DnsModifyRecordsInSet with APPEND option
                // Options: DNS_UPDATE_APPEND (0x1) to add the record
                // All other parameters can be IntPtr.Zero for default behavior
                result.status = DnsManagement.DnsModifyRecordsInSet(
                    pAddRecord,           // pAddRecords (linked list of records to add)
                    IntPtr.Zero,          // pDeleteRecords (no records to delete)
                    DnsOptions.DNS_UPDATE_APPEND, // options
                    IntPtr.Zero,          // hCredentials (no special credentials)
                    IntPtr.Zero,          // sockAddrArray (use default/configured DNS servers)
                    IntPtr.Zero);         // pReserved (must be null)

                 return result;
            }
            finally
            {
                // 5. CRITICAL: Free ALL unmanaged memory blocks manually.

                // Free the memory allocated for the pszName string
                if (pRecordName != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pRecordName);
                }

                // Free the memory allocated for the DnsRecord structure itself
                if (pAddRecord != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pAddRecord);
                }
            }
        }

        /// <summary>
        /// Replaces an existing A (Host) record in a DNS zone.
        /// </summary>
        /// <param name="recordName">The name of the host (e.g., "www" or "@" for the zone root).</param>
        /// <param name="ipAddress">The new IPv4 address string (e.g., "192.168.1.100").</param>
        /// <param name="ttl">The Time-To-Live (TTL) for the record in seconds.</param>
        public static DnsQueryResult ReplaceARecord(string recordName, string ipAddress, uint ttl)
        {
            DnsQueryResult result = new();

            // 1. Validate and parse the IP Address
            if (!IPAddress.TryParse(ipAddress, out IPAddress ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Invalid IPv4 address provided.", nameof(ipAddress));
            }

            byte[] ipBytes = ip.GetAddressBytes();
            uint ipUint = BitConverter.ToUInt32(ipBytes, 0);

            IntPtr pRecordName = IntPtr.Zero;
            IntPtr pAddRecord = IntPtr.Zero;

            try
            {
                pRecordName = Marshal.StringToCoTaskMemUni(recordName);

                var record = new DnsManagement.DnsRecord
                {
                    pszName = pRecordName,
                    wType = DnsManagement.DnsRecordType.A,
                    dwTtl = ttl,
                    Flags = 0,
                    pNext = IntPtr.Zero,
                    Data = new DnsManagement.DnsData
                    {
                        A = new DnsManagement.DNS_A_DATA
                        {
                            IpAddress = ipUint
                        }
                    }
                };
                record.wDataLength = (ushort)Marshal.SizeOf(typeof(DnsManagement.DNS_A_DATA));

                pAddRecord = Marshal.AllocHGlobal(Marshal.SizeOf(record));
                Marshal.StructureToPtr(record, pAddRecord, false);

                // Use DNS_UPDATE_REPLACE to replace the record
                result.status = DnsManagement.DnsModifyRecordsInSet(
                    pAddRecord,
                    IntPtr.Zero,
                    DnsOptions.DNS_UPDATE_REPLACE,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                return result;
            }
            finally
            {
                if (pRecordName != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(pRecordName);

                if (pAddRecord != IntPtr.Zero)
                    Marshal.FreeHGlobal(pAddRecord);
            }
        }

        /// <summary>
        /// Deletes an A (Host) record from a DNS zone.
        /// </summary>
        /// <param name="recordName">The name of the host (e.g., "www" or "@" for the zone root).</param>
        /// <param name="ipAddress">The IPv4 address string of the record to delete.</param>
        public static DnsQueryResult DeleteARecord(string recordName, string ipAddress)
        {
            DnsQueryResult result = new();

            // 1. Validate and parse the IP Address
            if (!IPAddress.TryParse(ipAddress, out IPAddress ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("Invalid IPv4 address provided.", nameof(ipAddress));
            }

            byte[] ipBytes = ip.GetAddressBytes();
            uint ipUint = BitConverter.ToUInt32(ipBytes, 0);

            IntPtr pRecordName = IntPtr.Zero;
            IntPtr pDeleteRecord = IntPtr.Zero;

            try
            {
                pRecordName = Marshal.StringToCoTaskMemUni(recordName);

                var record = new DnsManagement.DnsRecord
                {
                    pszName = pRecordName,
                    wType = DnsManagement.DnsRecordType.A,
                    dwTtl = 0, // TTL is ignored for delete operations
                    Flags = 0,
                    pNext = IntPtr.Zero,
                    Data = new DnsManagement.DnsData
                    {
                        A = new DnsManagement.DNS_A_DATA
                        {
                            IpAddress = ipUint
                        }
                    }
                };
                record.wDataLength = (ushort)Marshal.SizeOf(typeof(DnsManagement.DNS_A_DATA));

                pDeleteRecord = Marshal.AllocHGlobal(Marshal.SizeOf(record));
                Marshal.StructureToPtr(record, pDeleteRecord, false);

                // Use DNS_UPDATE_REMOVE to delete the record
                result.status = DnsManagement.DnsModifyRecordsInSet(
                    IntPtr.Zero,           // pAddRecords (no records to add)
                    pDeleteRecord,         // pDeleteRecords (linked list of records to delete)
                    DnsOptions.DNS_UPDATE_REMOVE,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                return result;
            }
            finally
            {
                if (pRecordName != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(pRecordName);

                if (pDeleteRecord != IntPtr.Zero)
                    Marshal.FreeHGlobal(pDeleteRecord);
            }
        }

        // DnsQuery_A return codes: 0 = ERROR_SUCCESS
        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_A", CharSet = CharSet.Ansi)]
        private static extern int DnsQuery(string pszName, ushort wType, uint options, IntPtr pServers, out IntPtr ppQueryResults, IntPtr pReserved);

        [DllImport("dnsapi.dll")]
        private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);
        private static nint GetNameServerInPtr(string nameServer)
        {
            nint pServerArray;
            if (!IPAddress.TryParse(nameServer, out var serverIp) || serverIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new Exception("Server must be an IPv4 address.");

            int count = 1;
            int size = sizeof(uint) * (1 + count); // AddrCount + addresses
            pServerArray = Marshal.AllocHGlobal(size);
            // Write count
            Marshal.WriteInt32(pServerArray, count);
            // Write the IPv4 address bytes as a uint (little-endian on Windows)
            var bytes = serverIp.GetAddressBytes();
            uint addr = BitConverter.ToUInt32(bytes, 0);
            Marshal.WriteInt32(pServerArray, sizeof(uint), (int)addr);
            return pServerArray;
        }

        public static DnsQueryResult GetARecord(string recordName, string nameServer)
        {
            IntPtr pServerArray = IntPtr.Zero;
            IntPtr resultPtr = IntPtr.Zero;
            DnsQueryResult result = new();

            try
            {
                // If a server is provided, construct a PIP4_ARRAY structure in unmanaged memory:
                // struct IP4_ARRAY { DWORD AddrCount; DWORD AddrArray[AddrCount]; };
                if (!string.IsNullOrWhiteSpace(nameServer))
                {
                    pServerArray = GetNameServerInPtr(nameServer);
                }

                int status;
                var stopwatch = new Stopwatch();
                stopwatch.Start();
                // Query for A records
                // no cached results and TCP only
                result.status = DnsQuery(recordName, (ushort)DnsRecordType.A, 0x0000000A, pServerArray, out resultPtr, IntPtr.Zero);

                if (result.status != 0) // non-zero => failure
                {
                    return result;
                }

                IntPtr current = resultPtr;

                // compute offset to Data field inside DNS_RECORD
                int dataOffset = Marshal.OffsetOf(typeof(DnsRecord), "Data").ToInt32();

                while (current != IntPtr.Zero)
                {
                    // Marshal DNS_RECORD header
                    var record = Marshal.PtrToStructure<DnsRecord>(current);

                    if (record.wType == DnsRecordType.A)
                    {
                        // The A record data is located at current + dataOffset
                        IntPtr aDataPtr = IntPtr.Add(current, dataOffset);
                        var aData = Marshal.PtrToStructure<DNS_A_DATA>(aDataPtr);

                        // Convert uint IP to byte[] then to IPAddress
                        var ipBytes = BitConverter.GetBytes(aData.IpAddress);
                        var ip = new IPAddress(ipBytes);
                        result.records.Add(ip.ToString());
                    }

                    current = record.pNext;
                }
                stopwatch.Stop();

                //System.Diagnostics.Debug.WriteLine($"Took dnsapi.dll {stopwatch.Elapsed.TotalNanoseconds}ns");
                //System.Diagnostics.Debug.WriteLine($"Took dnsapi.dll {stopwatch.Elapsed.TotalMicroseconds}microseconds");
                //System.Diagnostics.Debug.WriteLine($"Took dnsapi.dll {stopwatch.Elapsed.TotalMilliseconds}ms");

                return result;
            }
            finally
            {
                if (resultPtr != IntPtr.Zero)
                {
                    // Free the records returned by DnsQuery
                    DnsRecordListFree(resultPtr, 0);
                }

                if (pServerArray != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pServerArray);
                }
            }
        }
    }
}
