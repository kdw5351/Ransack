#pragma once

#include <cstddef>

namespace WinApi {

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned long long ULONGLONG;
typedef std::size_t SIZE_T;

typedef BOOL (__stdcall *PHANDLER_ROUTINE)(DWORD CtrlType);

typedef struct _PROCESS_MEMORY_COUNTERS_EX {
  DWORD     cb;
  DWORD     PageFaultCount;
  SIZE_T    PeakWorkingSetSize;
  SIZE_T    WorkingSetSize;
  SIZE_T    QuotaPeakPagedPoolUsage;
  SIZE_T    QuotaPagedPoolUsage;
  SIZE_T    QuotaPeakNonPagedPoolUsage;
  SIZE_T    QuotaNonPagedPoolUsage;
  SIZE_T    PagefileUsage;
  SIZE_T    PeakPagefileUsage;
  SIZE_T    PrivateUsage;
} PROCESS_MEMORY_COUNTERS_EX;

static const DWORD GENERIC_WRITE = 0x40000000L;
static const DWORD FILE_SHARE_READ = 0x00000001;
static const DWORD FILE_SHARE_WRITE = 0x00000002;
static const DWORD CREATE_ALWAYS = 2;
static const DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;
static const DWORD OPEN_ALWAYS = 4;
static const DWORD FILE_APPEND_DATA = 0x00000004;
static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)-1;

extern "C" __declspec(dllimport) HANDLE __stdcall CreateFileA(
    const char *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    void *lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

extern "C" __declspec(dllimport) BOOL __stdcall WriteFile(
    HANDLE hFile, const void *lpBuffer, DWORD nNumberOfBytesToWrite,
    DWORD *lpNumberOfBytesWritten, void *lpOverlapped);

extern "C" __declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE hObject);
extern "C" __declspec(dllimport) BOOL __stdcall MoveFileA(
    const char *lpExistingFileName, const char *lpNewFileName);
extern "C" __declspec(dllimport) unsigned long long __stdcall GetTickCount64();
extern "C" __declspec(dllimport) DWORD __stdcall GetLastError();
extern "C" __declspec(dllimport) DWORD __stdcall GetModuleFileNameA(
    void *hModule, char *lpFilename, DWORD nSize);
extern "C" __declspec(dllimport) DWORD __stdcall GetCurrentDirectoryA(
    DWORD nBufferLength, char *lpBuffer);

typedef struct _MEMORY_BASIC_INFORMATION {
  void *BaseAddress;
  void *AllocationBase;
  DWORD AllocationProtect;
  std::size_t RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
} MEMORY_BASIC_INFORMATION;

extern "C" __declspec(dllimport) std::size_t __stdcall VirtualQuery(
    const void *lpAddress, MEMORY_BASIC_INFORMATION *lpBuffer, std::size_t dwLength);

extern "C" __declspec(dllimport) HANDLE __stdcall GetCurrentProcess();

extern "C" __declspec(dllimport) BOOL __stdcall CreateDirectoryA(
    const char *lpPathName, void *lpSecurityAttributes);

extern "C" __declspec(dllimport) BOOL __stdcall SetConsoleCtrlHandler(
    PHANDLER_ROUTINE HandlerRoutine, BOOL Add);

extern "C" __declspec(dllimport) BOOL __stdcall K32GetProcessMemoryInfo(
    HANDLE Process, PROCESS_MEMORY_COUNTERS_EX *ppsmemCounters, DWORD cb);

extern "C" __declspec(dllimport) __declspec(noreturn) void __stdcall
ExitProcess(unsigned int uExitCode);

}
