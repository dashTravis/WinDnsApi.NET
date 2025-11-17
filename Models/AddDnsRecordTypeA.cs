namespace WinDnsApi.NET.Models
{
    public class AddDnsRecordTypeA
    {
        public string recordName { get; set; }
        public string ipAddress { get; set; }
        public int ttl { get; set; }

        public AddDnsRecordTypeA (string recordName, string zoneName, string ipAddress, int ttl = 60)
        {
            this.recordName = recordName;
            this.ipAddress = ipAddress;
            this.ttl = ttl;
        }

        public AddDnsRecordTypeA()
        {

        }
    }
}
