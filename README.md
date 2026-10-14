Small tool to read SCCM registry information from a Primary Site Server (PSS) or Distribution Point (DP) over winreg. It reports site and management point values, a listed site database server, and DP registry flags for anonymous access and PXE. Registry keys and flags do not independently verify site roles, SQL connectivity, or a working PXE responder. PXE output combines the `IsPXE` and `IsActive` registry values: `1/1` indicates responses are configured, `1/0` means the PXE support flag is set but the response flag is off, `0/1` is inconsistent, and `0/0` means disabled. Missing values are reported without assuming their state.

Usage:
```
pssrecon -u <USER> -p <PASS> -d <DOMAIN> -host <PRIMARY SITE SERVER>
```
Example:
```
pssrecon -u lowpriv -p password -d corp.local -host pss.corp.local

[i] SCCM registry settings available
[+] Site Code Found: COR
[+] Site Server Found: SCCM.corp.local
[+] Management point listed: http://SCCM.corp.local
[+] Management point listed: http://SCCMMP.corp.local
[i] MP registry subkey present
[+] Site database server listed: SCCMDB01.CORP.LOCAL

pssrecon -u lowpriv -p password -d corp.local -host dp.corp.local

[i] SCCM registry settings available
[+] Site Code Found: COR
[+] Site Server Found: SCCM.CORP.local
[+] Management point listed: http://SCCM.corp.local
[+] Management point listed: http://SCCMMP.corp.local
[+] Anonymous access enabled in DP registry
[+] PXE enabled for responses in registry (IsPXE=1, IsActive=1)

```
