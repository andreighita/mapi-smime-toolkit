#pragma once
#include "stdafx.h"
#include <MAPI.h>
#include <mapix.h>
#include <mapiutil.h>
#define PR_SECURITY_PROFILES    PROP_TAG(PT_MV_BINARY, 0x355)
const GUID CDECL GUID_Dilkie = { 0x53bc2ec0, 0xd953, 0x11cd,{ 0x97, 0x52, 0x00, 0xaa, 0x00, 0x4a, 0xe4, 0x0e } };
#define	MAPI_FORCE_ACCESS		((ULONG) 0x00080000)

HRESULT Logon(LPMAPISESSION * lppSession);
HRESULT Logon(LPWSTR lpwsProfileName, LPMAPISESSION * lppSession);