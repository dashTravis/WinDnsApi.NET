# WinDnsApi.NET

A REST-based API that wraps native Windows DNS client calls via the `dnsapi.dll` library. Designed to enable DNS dynamic updates and queries through a modern RESTful interface.

## Why?

This project is an exploratory Proof of Concept demonstrating how to leverage the native Windows DNS API through a RESTful interface.

- **Windows Server Gap**: Windows Server lacks modern REST API support for managing DNS records, Active Directory, and Windows Services. This project bridges that gap using native Windows DNS APIs.
- **Automation**: Enables automated DNS record management from Windows environments via REST calls.
- **RFC Compliance**: Uses the standard Windows DNS API implementation following RFC specifications, allowing potential compatibility with non-Windows DNS servers (not tested).

## What Does It Do?

This project utilizes the native Windows DNS API (via P/Invoke to `dnsapi.dll`) to perform:
- **DNS Dynamic Updates** - Create, update, and delete DNS records. Currently limited to A records.
- **DNS Queries** - Query DNS servers for A records

## Installation & Setup
- `DefaultNameServer` in appsettings.json must be configured to point to the target DNS server.
- Leave it blank to use the local machine's DNS server.
- Uses DNS over TCP for lookups for reliability. There's a known issue in demanding use cases where the host will run out of ports due to TCP wait states. Switch to UDP if needed.

### Prerequisites
- .NET 10 or later
- Windows Server or Windows Client with DNS capabilities
- Appropriate DNS zone permissions for dynamic updates

### Getting Started

[Add installation and configuration steps here]

## API Endpoints

[Add endpoint documentation here with examples]

## Architecture

This project follows clean architecture principles with clear separation of concerns:

- **Controllers** - HTTP request handling
- **Services** - Business logic and DNS operations
- **Models** - Request/response DTOs
- **Private/DnsManagement** - Native DNS API P/Invoke layer

## Alternative Windows DNS Management Approaches

Below is a comparison of different methods to manage DNS on Windows Server:

### RPC (DNSSERVER Protocol)

**Ports**: TCP 135 (endpoint mapper)

**Documentation**: [MS-DNSP: DNS Operations Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)

**Permissions**: Requires `DnsAdmin` role or delegated DNS permissions

**Tools & Usage**:
- DnsServer PowerShell cmdlets
- `dnscmd.exe` utility
- DNS Management Console (`dnsmgmt.msc`)

### WMI (Windows Management Instrumentation)

**Documentation**: [DNS WMI Provider Reference](https://learn.microsoft.com/en-us/windows/win32/dns/dns-wmi-provider-reference)

**Permissions**: Requires `DnsAdmin` permissions and WMI access on Domain Controllers

**Usage**: Limited modern adoption; primarily for legacy systems

### Windns API (dnsapi.dll) - *This Project*

**Ports**: UDP/TCP 53 (standard DNS port)

**Documentation**: [Windows DNS API Reference](https://learn.microsoft.com/en-us/windows/win32/api/windns/)

**Permissions**: Requires Create Object permissions on the target DNS zone for dynamic updates

**Tools & Usage**:
- Windows DNS Client (for DHCP registration)
- `ipconfig /registerdns`
- `nslookup`
- `Resolve-DnsName` PowerShell cmdlet

**Advantages**:
- Native RFC-compliant DNS protocol implementation
- Can target remote DNS servers
- Minimal dependencies
- Used by standard Windows tools

## Contributing

[Add contribution guidelines here]

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


## Acknowledgments

[Add any acknowledgments or references here]
