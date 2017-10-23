// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>



// TODO: reference additional headers your program requires here
#include <string>
#include <windows.h>
#include <iostream>
#define EC_HR(_hr) \
	do { \
		hr = _hr; \
		if (FAILED(hr)) \
		{ \
			std::wcout << L"FAILED! hr = " << std::hex << hr << std::endl << "Function: " << std::dec << __FUNCTION__ << std::endl << L"Line: " << __LINE__ << std::endl << L"File: " << __FILE__ << std::endl; \
			goto Error; \
		} \
	} while (0)

#define EC_BOOL(fTrue) \
	do { \
		if (!(fTrue)) \
		{ \
			std::wcout << L"The last operation did not succeed." << std::endl << "Function: " << std::dec << __FUNCTION__ << std::endl << L"Line: " << __LINE__ << std::endl << L"File: " << __FILE__ << std::endl; \
			std::wcout << L"Last error: " << std::hex << GetLastError(); \
			goto Error; \
		} \
	} while (0)