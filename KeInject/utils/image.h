#pragma once
#include <ntifs.h>

PVOID
NTAPI
AiFindExportedRoutineByName(
  _In_ PVOID DllBase,
  _In_ PANSI_STRING ExportName
  );
