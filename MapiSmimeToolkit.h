#include "stdafx.h"

enum {
	RUNNINGMODE_UNDEFINED, RUNNINGMODE_EDIT, RUNNINGMODE_CLEAR, RUNNINGMODE_LIST
};

enum {
	CERTMODE_UNDEFINED, CERTMODE_HASH, CERTMODE_LOOKUP, CERTMODE_ADLOOKUP
};

struct ToolkitOptions
{
	std::wstring wsOutlookProfileName;
	std::wstring wsSigningCertHash;
	std::wstring wsEncryptionCertHash;
	std::wstring wsEmailAddress;
	bool bDefaultOutlookProfile;
	bool bDefaultSecurityProfule;
	bool bDontSendCertificates;
	bool bOverWrite;
	std::string szDefaultSignatureHashOID;
	ULONG ulCertMode;
	ULONG ulRunningMode;
};


BOOL IsCorrectBitness();
std::string ConvertWideStringToString(LPCWSTR input);
BOOL ParseArgs(int argc, _TCHAR* argv[], ToolkitOptions * pToolkitOptions);