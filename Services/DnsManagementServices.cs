using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using WinDnsApi.NET.Private;
using WinDnsApi.NET.Services.Interfaces;
using static WinDnsApi.NET.Private.DnsManagement;

namespace WinDnsApi.NET.Services
{
    public class DnsManagementServices : IDnsManagementServices
    {
        public IActionResult HandleErrorResponse(int errorCode)
        {
            switch (errorCode)
            {
                case 9003:
                    return new NotFoundResult();
                default:
                    return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// Queries DNS for A records for the local or specified name server.
        /// </summary>
        public async Task<IActionResult> QueryARecordsAsync(string recordName, string nameServer = null)
        {
            if (string.IsNullOrWhiteSpace(recordName))
                throw new ArgumentException("Record name cannot be empty.", nameof(recordName));

            try
            {
                DnsQueryResult result = await Task.Run(() => DnsManagement.GetARecord(recordName, nameServer));

                if (result.status != 0)
                {
                    return HandleErrorResponse(result.status);
                }

                return new OkObjectResult(result.records);
            }
            catch (Exception ex)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }


        /// <summary>
        /// Creates an A record in the locally configured DNS server.
        /// </summary>
        public async Task<IActionResult> CreateARecordAsync(string recordName, string ipAddress, uint ttl)
        {
            if (string.IsNullOrWhiteSpace(recordName))
                throw new ArgumentException("Record name cannot be empty.", nameof(recordName));

            try
            {
                DnsQueryResult result = await Task.Run(() => DnsManagement.AddARecord(recordName, ipAddress, ttl));

                if (result.status != 0)
                {
                    return HandleErrorResponse(result.status);
                }

                return new OkResult();
            }
            catch (Exception ex)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// Updates an A record in the locally configured DNS server.
        /// </summary>
        public async Task<IActionResult> UpdateARecordAsync(string recordName, string ipAddress, uint ttl)
        {
            if (string.IsNullOrWhiteSpace(recordName))
                throw new ArgumentException("Record name cannot be empty.", nameof(recordName));

            try
            {
                DnsQueryResult result = await Task.Run(() => DnsManagement.ReplaceARecord(recordName, ipAddress, ttl));

                if (result.status != 0)
                {
                    return HandleErrorResponse(result.status);
                }

                return new OkResult();
            }
            catch (Exception ex)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// Deletes an A record in the locally configured DNS server.
        /// </summary>
        public async Task<IActionResult> DeleteARecordAsync(string recordName, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(recordName))
                throw new ArgumentException("Record name cannot be empty.", nameof(recordName));

            try
            {
                DnsQueryResult result = await Task.Run(() => DnsManagement.DeleteARecord(recordName, ipAddress));

                if (result.status != 0)
                {
                    return HandleErrorResponse(result.status);
                }

                return new OkResult();
            }
            catch (Exception ex)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

    }
}
