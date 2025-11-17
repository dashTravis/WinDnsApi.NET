using Microsoft.AspNetCore.Mvc;
using WinDnsApi.NET.Models;
using WinDnsApi.NET.Services.Interfaces;

namespace WinDnsApi.NET.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DnsController : ControllerBase
    {
        private readonly IDnsManagementServices _dnsService;
        private readonly ILogger<DnsController> _logger;
        private readonly IConfiguration _configuration;

        public DnsController(
            IDnsManagementServices dnsService, 
            ILogger<DnsController> logger,
            IConfiguration configuration)
        {
            _dnsService = dnsService ?? throw new ArgumentNullException(nameof(dnsService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        [HttpGet("{name}")]
        public async Task<IActionResult> GetAsync(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return BadRequest("Name is required.");

            // Use configuration value instead of hardcoded IP
            var defaultNameServer = _configuration["DnsConfiguration:DefaultNameServer"];
            
            return await _dnsService.QueryARecordsAsync($"{name}", defaultNameServer);
        }
            
        [HttpPost()]
        public async Task<IActionResult> AddAsync([FromBody] AddDnsRecordTypeA addDnsRecordTypeA)
        {
            if (string.IsNullOrWhiteSpace(addDnsRecordTypeA.recordName))
                return BadRequest("Name is required.");

            return await _dnsService.CreateARecordAsync(addDnsRecordTypeA.recordName, addDnsRecordTypeA.ipAddress, (uint)addDnsRecordTypeA.ttl);
        }

        [HttpPut()]
        public async Task<IActionResult> ReplaceAsync([FromBody] AddDnsRecordTypeA addDnsRecordTypeA)
        {
            if (string.IsNullOrWhiteSpace(addDnsRecordTypeA.recordName))
                return BadRequest("Name is required.");

            return await _dnsService.UpdateARecordAsync(addDnsRecordTypeA.recordName, addDnsRecordTypeA.ipAddress, (uint)addDnsRecordTypeA.ttl);
        }

        [HttpDelete]
        public async Task<IActionResult> DeleteAsync([FromBody] DeleteDnsRecordTypeA addDnsRecordTypeA)
        {
            if (string.IsNullOrWhiteSpace(addDnsRecordTypeA.recordName))
                return BadRequest("Name is required.");

            return await _dnsService.DeleteARecordAsync(addDnsRecordTypeA.recordName, addDnsRecordTypeA.ipAddress);
        }
    }
}
