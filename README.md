# ProcessFinder
Find process and startup arguments with syscalls only, as an example we are looking for svchost.exe with startup 
arguments ClipboardSvcGroup and cbdhsvc

An example how to find running process and startup arguments with syscalls:

ZwGetNextProcess (replace NtOpenProcess)

ZwQueryInformationProcess

ZwReadVirtualMemory

Only 64 bit is supported

Compile: csc.exe /platform:x64 /target:exe /unsafe ProcessFinder.cs


