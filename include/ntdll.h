#ifndef _NTDLL_H
#define _NTDLL_H

//
// Hack, because prototype in PH's headers and evntprov.h
// don't match.
//

#define EtwEventRegister __EtwEventRegisterIgnored

#include "phnt/phnt_windows.h"
#include "phnt/phnt.h"

#undef  EtwEventRegister

#endif
