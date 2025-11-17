using Microsoft.AspNetCore.Mvc;

namespace WinDnsApi.NET.Services.Interfaces
{
    public interface IDnsManagementServices
    {
        IActionResult HandleErrorResponse(int errorCode);

        /// <summary>
        /// Queries DNS for A records.
        /// </summary>
        /// <param name="recordName">DNS record name to query</param>
        /// <param name="nameServer">Optional DNS server to query. If null, uses default resolvers.</param>
        Task<IActionResult> QueryARecordsAsync(string recordName, string nameServer = null);

        /// <summary>
        /// Creates a new A record in DNS.
        /// </summary>
        /// <param name="recordName">Fully qualified record name</param>
        /// <param name="ipAddress">IPv4 address</param>
        /// <param name="ttl">Time-to-live in seconds</param>
        Task<IActionResult> CreateARecordAsync(string recordName, string ipAddress, uint ttl);

        /// <summary>
        /// Updates an existing A record in DNS.
        /// </summary>
        /// <param name="recordName">Fully qualified record name</param>
        /// <param name="ipAddress">New IPv4 address</param>
        /// <param name="ttl">Time-to-live in seconds</param>
        Task<IActionResult> UpdateARecordAsync(string recordName, string ipAddress, uint ttl);

        /// <summary>
        /// Deletes an A record from DNS.
        /// </summary>
        /// <param name="recordName">Fully qualified record name</param>
        /// <param name="ipAddress">IPv4 address of the record to delete</param>
        Task<IActionResult> DeleteARecordAsync(string recordName, string ipAddress);
    }
}
