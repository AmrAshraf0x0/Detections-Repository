# Group Policy Discovery: T1615
### DIS-E-1234-Windows_GPO_Enumeration

**Purpose**
Detects commands and processes used to enumerate GPOs on Windows endpoints only. Does **not** detect any modification commands to Windows GPOs. 

**Description**
- EventID `4688` detects all security logs from a Windows endpoint, and is used in combination with below commandlines. 
	- Rule is monitoring for following terms being contained in commandline for EventID:
	- `gpresult`
	- `Get-GPO`
	- `Get-DomainGPO`
	- `GPOAudit`
	- `GPORemoteAccessPolicy`
	- `Get-GPResultantSetOfPolicy`
	- `Get-GPPermission`
	These commands are commonly used to query and enumerate GPOs via the command prompt or powershell.
- Exclusions to rule are for accounts containing `$` as machine accounts are authorized to periodically enumerate GPOs. 
- Rule threshold is 3 observed commandlines from one host within 5 minutes (may need to be tuned for sensitivity after testing).

**Validation**
- [x] MITRE ATT&CK Detection DS0017: monitors for relevant commandline execution on Windows.
- [x] Atomic Red Team: covers red team tests 1-5 for t1615.

* * *
### References
- [MITRE ATT&CK T1615](https://attack.mitre.org/techniques/T1615/)
- [Atomic Red Team T1615](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1615/T1615.md)