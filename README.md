# WinDnsApi.NET
A REST-based API wrapping local native windows "client" DNS calls. These calls utilize the local windns API provided by the dnsapi.dll, included in Windows Client/Server.
This API would facilate automation needing to drive DNS updates in a RESTful format.



# Other Windows DNS Thoughts
## Ways in which to query a Windows Server with DNS Server role

### RPC (DNSSERVER ephemeral port (endpoint mapper)
#### Documentation
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a
#### Permissions
requires DnsAdmin permissions (or delegated equivalent)
#### Examples / How it's used
this is what DNSServer powershell tools use and what DNS snap-in uses

### WMI
#### Documentation
https://learn.microsoft.com/en-us/windows/win32/dns/dns-wmi-provider-reference
#### Permissions
require DnsAdmin permissions (or delegated equivalent) and WMI permissions on Domain Controllers
#### Examples / How it's used


### dns protocol (port 53) through dnsapi.dll (windns APIs)
#### Documentation
https://learn.microsoft.com/en-us/windows/win32/api/windns/
#### Permissions
#### Examples / How it's used
this is what nslookup and resolve-dnsname uses
