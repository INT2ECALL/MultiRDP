# MultiRDP
MultiRDP is a C#  consosle application to make multiple RDP (Remote Desktop) sessions possible by patching termsrv.dll correctly. For opsec considerations MultiRDP still uses cmd.exe to run sc services and impersonate as trustedinstaller. All versions of Windows 10 upto 21H1 (May 2021 update) are supported.

## Example

```
beacon> execute-assembly /root/Toolkits/MultiRDP.exe
[*] Tasked beacon to run .NET program: MultiRDP.exe
[+] host called home, sent: 113203 bytes
[+] received output:

-~=[Multiple RDP Sessions]=~-
* Allows system administrators to carryout administration tasks without disturbing the user
// With love from Snow Leopard //

[*] Found dll with version: 10.0.17763.1
[*] Stopping termservice

[+] received output:
[*] Patching...

[*] Patched successfully

[*] Setting the Registry entry
[*] Starting termservice again
[*] Finito
```

## Use Case
* Allow System Administrators to manage systems without disturbing or logging out other users.
* Take backups without affecting work.
