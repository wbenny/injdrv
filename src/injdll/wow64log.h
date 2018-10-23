#pragma once
#define NTDLL_NO_INLINE_INIT_STRING
#include <ntdll.h>

#ifdef __cplusplus
extern "C" {
#endif

//#define WOW64_LOG_FAKE_EXPORT_ENABLE

NTSTATUS
NTAPI
Wow64LogCreateExports(
  PVOID BaseAddress
  );

#ifdef __cplusplus
}
#endif
