#pragma once
#define SECURITY_WIN32 
#include "stdafx.h"
#include <objbase.h>
#include <wchar.h>
#include <activeds.h>
#include <Iads.h>
#include <sddl.h>
#include <wchar.h>
#include <initguid.h>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <strsafe.h>
#include <security.h>
#include <secext.h>
#include "SecurityProfile.h"
#define MAXBUFF 255
#define USES_IID_IADsADSystemInfo
#define USES_IID_IDirectorySearch
#define USES_IID_IADs

typedef IADs FAR * LPADS;
typedef IDirectorySearch FAR * LPDIRECTORYSEARCH;
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Activeds.lib")
#pragma comment (lib, "adsiid.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Secur32.lib")

std::wstring GetUserDn();
std::wstring FindPrimarySMTPAddress(std::wstring wszUserDn);
void FetchUserCertificates(std::wstring wszUserDn);
bool FetchADCertificate(DWORD * cbHash, LPBYTE * lpbHash, ULONG ulKeyUsage);