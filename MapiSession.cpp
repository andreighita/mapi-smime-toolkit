#include "stdafx.h"
#include "MapiSession.h"

HRESULT Logon(LPMAPISESSION * lppSession)
{
	HRESULT         hr = S_OK;            // MAPI return code.

	wprintf(L"Logging on..\n");
	EC_HR(MAPILogonEx(NULL,
		NULL,    // or specify the profile name here as an LPWSTR/LPTSTR
		NULL,
		MAPI_LOGON_UI |
		MAPI_NEW_SESSION |
		MAPI_NO_MAIL |
		MAPI_USE_DEFAULT,
		lppSession));

Error:
	goto Cleanup;
Cleanup:
	return hr;
}

HRESULT Logon(LPWSTR lpwsProfileName, LPMAPISESSION * lppSession)
{
	HRESULT         hr = S_OK;            // MAPI return code.

	wprintf(L"Logging on...\n");
	EC_HR(MAPILogonEx(NULL,
		LPTSTR(lpwsProfileName),    // or specify the profile name here as an LPWSTR/LPTSTR
		NULL,
		MAPI_LOGON_UI |
		MAPI_NEW_SESSION |
		MAPI_NO_MAIL | MAPI_UNICODE,
		lppSession));

Error:
	goto Cleanup;
Cleanup:
	return hr;
}