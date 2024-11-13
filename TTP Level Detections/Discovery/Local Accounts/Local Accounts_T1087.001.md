# Local Accounts t1087.001
### DIS-E-1234-Windows_Local_System_Account_Enumeration

**Purpose**
Detects commands used to enumerate local system accounts on Windows endpoints only. Does **not** detect any modification commands to Windows local accounts. 

**Description**
- EventID `4798` Signifies that a user's local group membership was enumerated.
- Rule is monitoring for following terms being contained in commandline regardless of the executing process alongside EventID:
	- `net user`
    - `net localgroup`    
    - `Get-LocalUser`    
    - `Get-WmiObject -Class Win32_UserAccount`
    - `Get-ADUser`
  Terms above are all key elements commonly seen in scripts which enumerate all local accounts upon execution in command prompt and powershell.
- Exclusions to rule are for accounts containing `tenable` and `$` as Tenable agents are authorized to run continuous auditing scripts across environment for compliance, and machine accounts are authorized to periodically enumerate local Windows accounts. 
- Rule threshold is 3 observed commandlines from one host within 5 minutes (may need to be tuned for sensitivity after testing).

**Validation**
- [x] MITRE ATT&CK Detection DS0017: monitors for EventID `4798`.
- [x] MITRE ATT&CK Detection DS0036: monitors for relevant commandline execution on Windows.
- [x] Atomic Red Team: covers red team tests 8-10 for t1087.001.

* * *
### DIS-E-1234-Linux_Local_System_Account_Enumeration
**Purpose**
Detects commands used to enumerate local system accounts on Linux endpoints only. Does **not** detect any modification commands to Linux local accounts. 

**Description**
- Monitors occurence of `/var/log/lastlog` file binary log which stores the timestamp and originating host of the last login for each user on a Linux system.
- Monitors commandline snippet `x:0` which typically appears in Linux user account entries, particularly in /etc/passwd (i.e.: `root:x:0:0:root:/root:/bin/bash`)
- Monitors various ways to access or display sensitive user account files `passwd`, `shadow`, and `sudoers` from commandline.
- Monitors `id` which is used to query user accound permissions from the commandline.
- Monitors `/lsof` and `-u` which is used to query open files by a specific user in commandline. 
- There currently is no exclusions or thresholds set for the rule as there is a limited number of Linux hosts in the environment which prevents tuning as of now. 

**Validation**
- [x] MITRE ATT&CK Detection DS0022: monitors for relevant commandline execution on Windows.
- [x] MITRE ATT&CK Detection DS0036: monitors for relevant commandline execution on Linux.
- [x] Atomic Red Team: covers red team tests 1-7 for t1087.001.

* * *
### References
[MITRE ATT&CK T1087.001](https://attack.mitre.org/techniques/T1087/001/)
[Atomic Red Team T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md)
[Cyber Kill Chain Commentary" T1087.001](https://cyber-kill-chain.ch/techniques/T1087/001/)