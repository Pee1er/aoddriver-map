Title: AMD OverDrive AODDriver.sys physical memory map

Vendor: Advanced Micro Devices, Inc.
Product: AMD OverDrive
Component: AODDriver.sys
SHA-256: 8a982eed9cbc724d50a9ddf4f74ecbcd67b4fdcd9c2bb1795bc88c2d9caf7506
MD5: c5b8e612360277ac70aa328432a99fd6
SHA-1: f5bafebfbfb67a022452870289ac7849e9ee1f61
Size: 6144 bytes
PE timestamp: 2007-10-11 06:26:50 UTC
Authenticode status: NotSigned
Device: \\.\ASUDriver
PDB: F:\SVN\ASU\Source\Windows\debug\amd64\AODDriver.pdb

CVE:

Description:
AODDriver.sys IOCTL 0x81112EF0 is METHOD_BUFFERED. The caller supplies a physical address, a cache type, and a length. The driver passes that address to MmMapIoSpace and maps the range into the calling process. This file has no VERSIONINFO. Local account aida-low sent this IOCTL. That account wrote its own bytes through the returned mapping into a page an administrator was holding.

Access:
On 2026-11-02, on an isolated Windows 10 virtual machine, an administrator loaded a test-signed copy of this file. The unsigned original did not start: service start returned Windows error 577, and Code Integrity event 3004 said the file hash could not be found. The running image is that same file with a local test signature appended. Its SHA-256 is af27ce49251f48723a17114068b9b8c512d96b908fc45a3791ed8fe12f05b53c and its size is 7856 bytes. The device security descriptor was:

O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW)

Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA. Local account aida-low belongs to Users. That account opened \\.\ASUDriver and sent IOCTL 0x81112EF0. The administrator locked one of its own pages, resolved that page, and watched the first byte. The administrator did not send the IOCTL.

Map result:
On 2026-11-02 the administrator held physical address 0x1062e8000. aida-low sent IOCTL 0x81112EF0 for that address and wrote 0x5A, then 0xA5, through the mapping returned to its process. Its result showed administrators_sid=absent, marker=0x5a map=0x5a, marker=0xa5 map=0xa5, and IOCTL PASS. The administrator's result showed saw page=0x5a and saw page=0xa5. The test did not show a crash.

Other reports:
CVE-2019-7247 describes AODDriver2.sys in AMD OverDrive. That issue is IOCTL 0x81112ee0 exposing WRMSR. It does not describe this AODDriver.sys image or IOCTL 0x81112EF0. This note identifies the tested file by the hashes above.

Suggested fix: on this IOCTL, map only a physical address chosen inside the driver, and limit access to \\.\ASUDriver to Administrators and SYSTEM.
