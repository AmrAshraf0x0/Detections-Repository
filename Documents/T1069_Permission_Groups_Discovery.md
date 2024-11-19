# Groups Permissions Discovery: T1069
### DIS-E-1234-Windows_Local_Groups_Permissions_Enumeration

**Sub-technique covered:** T1069.001

**Purpose**
Detects commands and processes used to enumerate local group permissions on Windows endpoints only. Does **not** detect any modification commands to Windows local groups. 

**Description**
- EventIDs `4798` and `4799` detect events where a user’s local group membership is queried. This Event ID is directly associated with local group permission enumeration activities.
- Rule is monitoring for following terms being contained in commandline regardless of the executing process alongside EventID:
      - `net localgroup`       
      - `net user`   
      - `Get-LocalGroupMember`
      - `Get-LocalGroup`
      - `Get-WmiObject Win32_Group`
      - `wmic group`
	These commands are commonly used to query and enumerate local group permissions via the command prompt or powershell.
- Exclusions to rule are for accounts containing `tenable` and `$` as Tenable agents are authorized to run continuous auditing scripts across environment for compliance, and machine accounts are authorized to periodically enumerate local Windows accounts. 
- Rule threshold is 3 observed commandlines from one host within 5 minutes (may need to be tuned for sensitivity after testing).

**Validation**
- [x] MITRE ATT&CK Detection DS0017: monitors for relevant commandline execution on Windows.
- [x] MITRE ATT&CK Detection DS0036: monitors for EventIDs `4798` and `4799` on Windows.
- [x] Atomic Red Team: covers red team tests 2-6 for t1069.001.

* * *
### DIS-E-1234-Windows_Domain_Groups_Permissions_Enumeration

**Sub-technique covered:** T1069.002

**Purpose**
Detects commands and processes used to enumerate domain group permissions on Windows endpoints only. Does **not** detect any modification commands to Windows domain groups. 

**Description**
- Rule is monitoring for following terms being contained in commandline regardless of the executing process alongside EventID:
	- `get-ADPrincipalGroupMembership`
	- `Find-LocalAdminAccess` and `Invoke-EnumerateLocalAdmin`
	- `Find-GPOComputerAdmin`
	- `get-aduser -f * -pr DoesNotRequirePreAuth`
	- `Get-AdGroup` and `Get-DomainGroup`
	- `adsisearcher`
	- `useraccountcontrol`
	- `Get-DomainGroup`
	- `net group`
	- `net localgroup`
	These commands are commonly used to query and enumerate domain group permissions via the command prompt or powershell.
- Rule is monitoring the following utilities/executables creating process on host to enumerate domain group permissions:
	- `ldifde.exe`
	- `adfind.exe`
- Exclusions to rule are for accounts containing `tenable` and `$` as Tenable agents are authorized to run continuous auditing scripts across environment for compliance, and machine accounts are authorized to periodically enumerate local Windows accounts. 
- Rule threshold is 3 observed commandlines from one host within 5 minutes (may need to be tuned for sensitivity after testing).

**Validation**
- [x] MITRE ATT&CK Detection DS0017: monitors for relevant commandline execution on Windows.
- [x] MITRE ATT&CK Detection DS0009: monitors process creation  Windows.
- [x] Atomic Red Team: covers red team tests 1-13 for t1069.002.
	* Atomic test 1 for sub-technique t1069.002 contains overlap with atomic tests 2 and 3 for sub-technique t1069.001. Two rules might fire for these atomic tests. 

* * *
### DIS-E-1234-Linux_Local_Groups_Permissions_Enumeration

**Sub-technique covered:** T1069.001

**Purpose**
Detects commands and processes used to enumerate local group permissions on Linux endpoints only. Does **not** detect any modification commands to Linux local groups. 

**Description**
- Monitors specific binaries commonly used for enumerating local groups, including:
	- `/cat`
	- `/getent`
	- `/groups`
	- `/usr/bin/id`
- Monitors Linux commands being present in the commandline field which are commonly used to query local group permissions These include:
	- `/etc/group`
	- `/etc/passwd`
	- `getent group`
	- `groups`
	- `id -Gn`

**Validation**
- [x] MITRE ATT&CK Detection DS0017: monitors for relevant commandline execution on Linux.
- [x] Atomic Red Team: covers red team test 1 for t1069.001.

* * *
### References
- [MITRE ATT&CK T1087.001](https://attack.mitre.org/techniques/T1069/001/)
- [MITRE ATT&CK T1087.002](https://attack.mitre.org/techniques/T1069/002/)
- [Atomic Red Team T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md)
- [Atomic Red Team T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md)
- [Windows SID Index](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
