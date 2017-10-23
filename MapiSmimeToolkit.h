#include "stdafx.h"

enum {
	RUNNINGMODE_UNDEFINED, RUNNINGMODE_EDIT, RUNNINGMODE_CLEAR, RUNNINGMODE_LIST
};

enum {
	CERTMODE_UNDEFINED, CERTMODE_HASH, CERTMODE_LOOKUP
};

struct ToolkitOptions
{
	std::wstring wsOutlookProfileName;
	std::wstring wsSigningCertHash;
	std::wstring wsEncryptionCertHash;
	std::wstring wsEmailAddress;
	bool bDefaultOutlookProfile;
	bool bDefaultSecurityProfule;
	bool bOverWrite;
	ULONG ulCertMode;
	ULONG ulRunningMode;
};


BOOL IsCorrectBitness();
