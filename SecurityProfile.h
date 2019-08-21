#pragma once
#include "stdafx.h"
#define USES_IID_IMAPIProp
#include <initguid.h>
#include <MAPIUtil.h>
#include <MAPIGuid.h>
#include <Windows.h>
#include "MapiSession.h"
#include <Wincrypt.h>
#include <algorithm>
#include <cctype>
#pragma comment(lib, "crypt32.lib")

#define PR_CERT_PROP_VERSION            PROP_TAG(PT_LONG,       0x0001)
#define PR_CERT_ASYMETRIC_CAPS          PROP_TAG(PT_BINARY,     0x0002)
#define PR_CERT_MESSAGE_ENCODING        PROP_TAG(PT_LONG,       0x0006)
#define PR_CERT_SIGN_CERTIFICATE        PROP_TAG(PT_CERTIFICATE, 0x0008)
#define PR_CERT_SIGN_CERTIFICATE_BIN    PROP_TAG(PT_BINARY,     0x0008)
#define PR_CERT_SIGN_SHA1_HASH          PROP_TAG(PT_BINARY,     0x0009)
#define PR_CERT_DISPLAY_NAME_A          PROP_TAG(PT_STRING8,    0x000B)
#define PR_CERT_DISPLAY_NAME_W          PROP_TAG(PT_UNICODE,    0x0051)
#define PR_CERT_DEFAULTS                PROP_TAG(PT_LONG,       0x0020)
#define PR_CERT_KEYEX_SHA1_HASH         PROP_TAG(PT_BINARY,     0x0022)

// http://support.microsoft.com/kb/312900
#define PR_CERT_DEFAULTS                PROP_TAG(PT_LONG,       0x0020)
// Values for PR_CERT_DEFAULTS
#define MSG_DEFAULTS_NONE               0
#define MSG_DEFAULTS_FOR_FORMAT         1 // Default certificate for S/MIME.
#define MSG_DEFAULTS_GLOBAL             2 // Default certificate for all formats.
#define MSG_DEFAULTS_SEND_CERT          4 // Send certificate with message.

union _PVSec {
	LONG                l;
	SBinary             bin;
	LPSTR               lpszA;
	LPWSTR              lpszW;
	PCCERT_CONTEXT      pccert;
	FILETIME            ft;
};

union _PVSecRead {
	LONG	l;

	BYTE	bytes[];
};

typedef struct _SSecPropValue {
	WORD        wTag;           // Tag of data
	WORD        wSize;          // size of data - including structure
	union _PVSec      Value;         // data for tag
} SSecPropValue, FAR  * LPSSecPropValue;

typedef struct _SSecPropValueRead {
	WORD        wTag;           // Tag of data
	WORD        wSize;          // size of data - including structure
	union _PVSecRead      Value;         // data for tag
} SSecPropValueRead, FAR  * LPSSecPropValueRead;

typedef struct _SSecPropArray {
	ULONG			cProps;		// Tag of data
	_SSecPropValue	*aProp;	// data for tag
} SSecPropArray, FAR  * LPSSecPropArray;

typedef struct _SSecProf {
	WORD certPropVersionTag;
	WORD certPropVersionSize;
	LONG certPropVersionValue;

	WORD certMessageEncodingTag;
	WORD certMessageEncodingSize;
	LONG certMessageEncodingValue;

	WORD certDefaultsTag;
	WORD certDefaultsSize;
	LONG certDefaultsValue;

	WORD certDisplayNameATag;
	WORD certDisplayNameASize;
	WORD certDisplayNameAcb;
	LPSTR certDisplayNameAValue;

	WORD certDisplayNameWTag;
	WORD certDisplayNameWSize;
	WORD certDisplayNameWcb;
	LPWSTR certDisplayNameWValue;

	WORD certKeyexSha1Tag;
	WORD certKeyexSha1Size;
	WORD certKeyexSha1cb;
	LPBYTE certKeyexSha1lpb;

	WORD certSignSha1Tag;
	WORD certSignSha1Size;
	WORD certSignSha1cb;
	LPBYTE certSignSha1lpb;

	WORD certAsymetricCapsTag;
	WORD certAsymetricCapsSize;
	WORD certAsymetricCapscb;
	LPBYTE certAsymetricCapslpb;
} FAR * LPSSECPROF;

struct SecProfEntry
{
	BOOL bDefaultSecuritySettings;
	BOOL bSendWithSignedMessage;
	ULONG ulCertPropVersion;
	ULONG ulMessageEncoding;
	ULONG ulCertDefaults;
	std::string sSecurityProfileName;
	std::wstring wsSecurityProfileName;
	std::wstring wsSignatureCertificateHash;
	std::wstring wsEncryptionCertificateHash;
} ;


struct CERT_DATA
{
	FILETIME notAfter;
	DWORD* pHashSize;
	BYTE* pHash;
};

HRESULT HrCertFindCertificateInStoreBySubject(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, PCCERT_CONTEXT * ppNextCert, std::wstring wszLookupString);
HRESULT HrCertFindCertificateInStoreByHash(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, PCCERT_CONTEXT * ppNextCert, DWORD cb, LPBYTE lpb);
std::wstring BinToHexWString(_In_opt_count_(cb) const BYTE bytes[], size_t cb, bool bAnsi, bool bBinary);
BOOL CertificateFound(std::wstring wszSmtpAddress, DWORD * cbHash, LPBYTE * lpbHash, ULONG ulKeyUsage);
BOOL LookUpEncryptionCertificate(std::wstring wszSmtpAddress, PCCERT_CONTEXT * pCertContext);
void ListSecurityProfiles(ULONG cSecProfileEntry, SecProfEntry * pSecProfileEntry);
HRESULT SaveSecurityProfile(LPMAPISESSION lpSession, LPSBinary lpProfile, bool bOverwrite, bool bDefaultProfile);
HRESULT GetSecurityProfiles(LPMAPISESSION lpSession, SecProfEntry * pSecProfileEntry);
HRESULT GetSecurityProfileCount(LPMAPISESSION lpSession, ULONG * cSecProfileEntry);
BOOL IsCertNewer(FILETIME ftFirstCert, FILETIME ftSecondCert);
std::wstring ValidateSecurityProfileName(ULONG cSecProfileEntry, SecProfEntry * pSecProfEntry, std::wstring wsSecurityProfileName, int iAttempt);
void _stdcall StringtoByteArray(std::wstring inputString, ULONG * cb, LPBYTE pb);
BOOL FindCertificate(std::wstring binaryString, DWORD * cbHash, LPBYTE * lpbHash);
 HRESULT NewSecurityProfile(DWORD cbSignHash, LPBYTE lpbSignHash, DWORD cbEncHash, LPBYTE lpbEncHash, std::wstring wsProfileName, bool bDefaultProfile, std::string szDefaultSignatureHashOID, LPSBinary lpProfile);
bool IsRightCertUsage(PCCERT_CONTEXT pCCert, ULONG ulKeyUsage);
HRESULT HrCertFindCertificateInStoreBySubject(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, PCCERT_CONTEXT * ppNextCert, std::wstring wszLookupString, ULONG ulKeyUsage);
HRESULT ClearSecurityProfiles(LPMAPISESSION lpSession);