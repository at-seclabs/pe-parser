# PE file parser

A PE file parser written in C++.

#### Purposes
This project whas coded while exploring Windows Internals. 

Allows us to validate the PE format, explore modules imports and functions, and exports.

Output example:
```powershell
=== PE Parser v1.0 ===
File: C:\Users\user\Documents\PeParser\x64\Release\mimikatz.exe
Architecture x64

== OPTIONAL HEADER ==
Magic: 0x20b
Entry point : 0xbcd0c
Image base : 0x140000000
Size of image : 0x133000

=== SECTIONS (6) ===
.text VA: 0x1000 Size: 0xc2c00 [R-X]
.rdata VA: 0xc4000 Size: 0x58800 [R--]
.data VA: 0x11d000 Size: 0x6600 [RW-]
.pdata VA: 0x125000 Size: 0x6400 [R--]
.rsrc VA: 0x12c000 Size: 0x4000 [R--]
.reloc VA: 0x130000 Size: 0x2400 [R--]

== IMPORTS ==
-- Imported functions by: ADVAPI32.dll
CryptSetHashParam
CryptGetHashParam
CryptExportKey
CryptAcquireContextW
CryptSetKeyParam
CryptGetKeyParam
CryptReleaseContext
CryptDuplicateKey
CryptAcquireContextA
CryptGetProvParam
CryptImportKey
SystemFunction007
CryptEncrypt
CryptCreateHash
```

### Defensive perspectives:

Analyzing PE with a defensive perspective can reveal somme critical insights, well known by AV and used for static analysis.

In the current cas, the mimikatz tool PE was mapped in memory and the current insights are relevant:

#### Suspicious imports: 

- The **advapi32.dll** is imported.
This DLL (Advanced Windows 32 Base API) is a core operating system file in Microsoft Windows. Located in C:\Windows\System32, it provides essential functions for security, user account management, and Windows Registry manipulation. Errors regarding this file usually mean it is missing, corrupted, or blocked by malware

-**LsaOpenPolicy**, **LsaOpenSecret**, **LsaQuerySecret** functions are present in the tool. They are used to access secrets.

- **LsaQueryTrustedDomainInfoByName** is an Active Directory enumeration function.

- **OpenProcessToken**, **DuplicateTokenEx**, these are authentication functions. 

- **CryptAcquireContextW**, **CryptDecrypt**, **CryptImportKey**, ciphering functions. 

- **SystemFunction001**, **SystemFunction006**, **SystemFunction007**, undocumented functions.

All these elements are usefull insights, they are clearly indicating that the targeted programms will try to acccess to secrets.

#### Section size:

-The .text section:

```bash
.text VA: 0x1000 Size: 0xc2c00 [R-X]
```

The .text section is the primary segment that holds the application’s actual executable code and CPU instructions.

The current size of the .text is big (0xc2c00 hex is almost 800kb) may also be considered as relevant.


### Offensive perspectives:

The parser reveals suspicious imports. Two potential solutions here:

- Dynamic import resolution: GetProcAddress + LoadLibrary


- PEB walking or manual export table parsing


