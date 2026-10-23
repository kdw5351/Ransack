// ---------------------------------------------------------------------------
// win_const.h — Win32 constants for PinTool (-nostdinc safe)
//
// Why this file exists:
//   PinTool builds with `-nostdinc` to avoid pulling in MSVCRT/STL headers
//   that conflict with Pin's runtime. The Windows SDK macros (PAGE_*, MEM_*,
//   DELETE_FILE flags, etc.) defined in <winnt.h> / <memoryapi.h> are
//   therefore not in scope inside our .cpp files.
//
// Source of values:
//   Microsoft Windows SDK headers (Win10/Win11 v10.0.22621.0).
//     PAGE_*  : SDK winnt.h §"Page protection constants"
//     MEM_*   : SDK winnt.h §"Memory state constants"
//   Verified against:
//     https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery
//     https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
//
// These constants are part of the public Win32 ABI and have been stable
// since Windows NT 3.51. They are NOT secrets; copying them here is the
// canonical workaround for tools that must build without the SDK include
// path (PinTool, custom drivers, kernel debug helpers, etc.).
// ---------------------------------------------------------------------------
#ifndef RANSOMFLOW_WIN_CONST_H
#define RANSOMFLOW_WIN_CONST_H

// Page protection constants (winnt.h)
#ifndef PAGE_NOACCESS
#define PAGE_NOACCESS                   0x01
#endif
#ifndef PAGE_READONLY
#define PAGE_READONLY                   0x02
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE                  0x04
#endif
#ifndef PAGE_WRITECOPY
#define PAGE_WRITECOPY                  0x08
#endif
#ifndef PAGE_EXECUTE
#define PAGE_EXECUTE                    0x10
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ               0x20
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE          0x40
#endif
#ifndef PAGE_EXECUTE_WRITECOPY
#define PAGE_EXECUTE_WRITECOPY          0x80
#endif
#ifndef PAGE_GUARD
#define PAGE_GUARD                      0x100
#endif
#ifndef PAGE_NOCACHE
#define PAGE_NOCACHE                    0x200
#endif
#ifndef PAGE_WRITECOMBINE
#define PAGE_WRITECOMBINE               0x400
#endif

// Memory state constants (winnt.h)
#ifndef MEM_COMMIT
#define MEM_COMMIT                      0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE                     0x2000
#endif
#ifndef MEM_FREE
#define MEM_FREE                        0x10000
#endif

// Convenience masks used by ransomflow loop_detection
#define RANSOMFLOW_PAGE_EXEC_MASK       (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define RANSOMFLOW_PAGE_REJECT_MASK     (PAGE_GUARD | PAGE_NOACCESS)

#endif  // RANSOMFLOW_WIN_CONST_H
