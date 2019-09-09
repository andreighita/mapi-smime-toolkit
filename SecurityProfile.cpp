#include "stdafx.h"
#include "SecurityProfile.h"
#include <iostream>
#include <sstream>
#include <vector>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define GetWord(pwSrc)   (*(UNALIGNED WORD *)(pwSrc))

VOID WINAPI CryptFree(LPVOID pv)
{
	free(pv);
}

LPVOID WINAPI CryptAlloc(size_t cbSize)
{
	return malloc(cbSize);
}

CRYPT_ENCODE_PARA       CryptEncode = {
	sizeof(CryptEncode), CryptAlloc, CryptFree
};


void _stdcall StringtoByteArray(std::wstring inputString, ULONG * cb, LPBYTE pb)
{
	int numOfBytes = 0;
	int numOfBytesl = 0;
	if (*cb != 0)
	{
		numOfBytes = *cb;
	}
	else
	{
		numOfBytes = inputString.size() / 2;
		numOfBytesl = inputString.length();
		memcpy(cb, &numOfBytes, sizeof(int));

	}

	if (pb)
	{
		byte * bytes = (byte *)malloc(numOfBytes);
		ZeroMemory(bytes, numOfBytes);
		for (int i = 0; i < numOfBytes; ++i)
		{
			std::wstring substr = inputString.substr((2 * i), 2);

			bytes[i] = (byte)wcstol(substr.c_str(), NULL, 16);
		}
		memcpy(pb, bytes, numOfBytes);
	}
}

// Adapted this from MFCMAPI's code, it returns a string representation of a byte array
std::wstring BinToHexWString(_In_opt_count_(cb) const BYTE bytes[], size_t cb, bool bAnsi, bool bBinary)
{
	std::wstring lpsz = L"";

	if (!cb)
	{
		lpsz += L"NULL";
	}
	else
	{
		for (ULONG i = 0; i < cb; i++)
		{
			wchar_t chr = L' ';
			if (bAnsi)
			{
				if (bBinary)
				{
					wchar_t buffer[10];
					wchar_t val = (wchar_t)bytes[i];
					int intval = (int)val;

					_itow_s(intval, buffer, 16);
					if (intval <= 15)
						lpsz += L"0";
					lpsz += +buffer;
				}
				else
				{
					chr = (wchar_t)bytes[i];
					lpsz += chr;
				}
			}
			else
			{
					chr = (wchar_t)bytes[i *2];
					lpsz += chr;
			}
		}
	}

	return lpsz;
}

BOOL FindCertificate(std::wstring binaryString, DWORD * cbHash, LPBYTE * lpbHash)
{
	HRESULT hr = S_OK;
	ULONG cb = 0;
	BYTE * pb = NULL;
	DWORD cbCertHash = 0;
	LPBYTE lpbCertHash = NULL;
	StringtoByteArray(binaryString, &cb, NULL);
	if (cb > 0)
	{
		pb = (BYTE*)malloc(cb);
		ZeroMemory(pb, cb);
	}
	StringtoByteArray(binaryString, &cb, pb);
	HCERTSTORE  hSystemStore = NULL;		// System store handle
	PCCERT_CONTEXT pNewCert = NULL;
	if (hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"MY"))                 // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	{
		printf("Open the MY system store. \n");
	}
	else
	{
		printf("Could not open the MY system store.\n");
		return S_FALSE;
	}

	printf("Looking up your certificate based on the thumbprint you've provided...\n");
	EC_HR(HrCertFindCertificateInStoreByHash(hSystemStore, NULL, &pNewCert, cb, pb));
	if (pNewCert)
	{
		wprintf(L"Certificate found.\n");
		//* pCertContext = pNewestCert;

		EC_BOOL(CertGetCertificateContextProperty(pNewCert, CERT_HASH_PROP_ID, NULL, &cbCertHash));
		EC_BOOL(lpbCertHash = (BYTE*)malloc(cbCertHash));
		EC_BOOL(CertGetCertificateContextProperty(pNewCert, CERT_HASH_PROP_ID, lpbCertHash, &cbCertHash));

		*cbHash = cbCertHash;
		*lpbHash = lpbCertHash;
		return true;
	}
	else return false;
Error:
	goto Cleanup;
Cleanup:
	return SUCCEEDED(hr);
}


BOOL CertificateFound(std::wstring wszSmtpAddress, DWORD * cbHash, LPBYTE * lpbHash, ULONG ulKeyUsage)
{
	HRESULT hr = S_OK;
	HCERTSTORE  hSystemStore = NULL;		// System store handle
	PCCERT_CONTEXT pOffsetCert = NULL;

	CERT_CONTEXT ccCertContext = { 0 };
	PCCERT_CONTEXT pNewestCert = &ccCertContext;
	DWORD cbCertHash = 0;
	LPBYTE lpbCertHash = NULL;
	ULONG cCertContext = 0;
	if (hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"MY"))                 // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	{
		printf("Open the MY system store.\n");
	}
	else
	{
		printf("Could not open the MY system store.\n");
		return S_FALSE;
	}

	//-------------------------------------------------------------------
	// Get certificates that have the string represented by wszSmtpAddress 
	// in their subject. 

	CERT_DATA newestCertData = { 0 };
	printf("Looking up your certificate based on the search string you've provided...\n");

	if SUCCEEDED(HrCertFindCertificateInStoreBySubject(hSystemStore, NULL, &pOffsetCert, wszSmtpAddress, ulKeyUsage))
	{
		memcpy((LPVOID)pNewestCert,(LPVOID)pOffsetCert, sizeof(CERT_CONTEXT));

		EC_BOOL(CertGetCertificateContextProperty(pOffsetCert, CERT_HASH_PROP_ID, NULL, &cbCertHash));
		EC_BOOL(lpbCertHash = (BYTE*)malloc(cbCertHash));
		EC_BOOL(CertGetCertificateContextProperty(pOffsetCert, CERT_HASH_PROP_ID, lpbCertHash, &cbCertHash));

		if (pNewestCert)
		{
			
			do {
				hr = HrCertFindCertificateInStoreBySubject(hSystemStore, pOffsetCert, &pOffsetCert, wszSmtpAddress, ulKeyUsage);
				if (S_OK == hr)
				{
					//lpSysTime = SYSTEMTIME();
					//converted = FileTimeToSystemTime(&pNewCert->pCertInfo->NotAfter, &lpSysTime);
					if (IsCertNewer(pOffsetCert->pCertInfo->NotAfter, pNewestCert->pCertInfo->NotAfter))
					{
						memcpy((LPVOID)pNewestCert, (LPVOID)pOffsetCert, sizeof(CERT_CONTEXT));
						EC_BOOL(CertGetCertificateContextProperty(pOffsetCert, CERT_HASH_PROP_ID, NULL, &cbCertHash));
						EC_BOOL(lpbCertHash = (BYTE*)malloc(cbCertHash));
						EC_BOOL(CertGetCertificateContextProperty(pOffsetCert, CERT_HASH_PROP_ID, lpbCertHash, &cbCertHash));

					}
				}

			} while (S_OK == hr);
		}

		if (S_OK != hr)
		{

		}
	}

	if (pNewestCert)
	{
		*cbHash = cbCertHash;
		//lpbHash = (LPBYTE*)malloc(sizeof(LPBYTE));
		*lpbHash = lpbCertHash;
		//memcpy(&lpbHash, &lpbCertHash, cbCertHash);
		return true;
	}
	else return false;

Error:
	goto Cleanup;
Cleanup:
	return SUCCEEDED(hr);
}

bool IsRightCertUsage(PCCERT_CONTEXT pCCert, ULONG ulKeyUsage)
{
	for (unsigned int i = 0; i < pCCert->pCertInfo->cExtension; i++)
	{
		std::string szKeyUsage = szOID_KEY_USAGE;
		if (strcmp(pCCert->pCertInfo->rgExtension[i].pszObjId, (LPSTR)szKeyUsage.c_str()) == 0)
		{
			DWORD   cbKeyUsage = 0;
			if (::CryptDecodeObject(CRYPT_ASN_ENCODING,
				szOID_KEY_USAGE,
				pCCert->pCertInfo->rgExtension[i].Value.pbData,
				pCCert->pCertInfo->rgExtension[i].Value.cbData,
				0, NULL, &cbKeyUsage))
			{
				CRYPT_BIT_BLOB* pKeyUsage = (CRYPT_BIT_BLOB*)::LocalAlloc(LPTR, cbKeyUsage);
				if (pKeyUsage)
				{
					if (::CryptDecodeObject(CRYPT_ASN_ENCODING,
						szOID_KEY_USAGE,
						pCCert->pCertInfo->rgExtension[i].Value.pbData,
						pCCert->pCertInfo->rgExtension[i].Value.cbData,
						0, pKeyUsage, &cbKeyUsage))
					{
						if (pKeyUsage->cbData >= 1)
						{
							if (pKeyUsage->pbData[0] & ulKeyUsage)
								return true;
							else
								return false;
						}
					}
				}
			}
		}
	}
	return false;
}

BOOL LookUpEncryptionCertificate(std::wstring wszSmtpAddress, PCCERT_CONTEXT * pCertContext)
{
	HRESULT hr = S_OK;
	HCERTSTORE  hSystemStore = NULL;		// System store handle
	PCCERT_CONTEXT pOffsetCert = NULL;   // Set to NULL for the first 
										 // call to
										 // CertFindCertificateInStore
	PCCERT_CONTEXT pNewCert = NULL;   // Set to NULL for the first 
									  // call to
									  // CertFindCertificateInStore
	PCCERT_CONTEXT pNewestCert = NULL;   // Set to NULL for the first 
										 // call to
										 // CertFindCertificateInStore



MAPIAllocateBuffer(sizeof(PCCERT_CONTEXT), (LPVOID*)&pNewestCert);
ZeroMemory(&pNewestCert, sizeof(PCCERT_CONTEXT));

ULONG cCertContext = 0;
if (hSystemStore = CertOpenStore(
	CERT_STORE_PROV_SYSTEM, // System store will be a 
							// virtual store
	0,                      // Encoding type not needed 
							// with this PROV
	NULL,                   // Accept the default HCRYPTPROV
	CERT_SYSTEM_STORE_CURRENT_USER,
	// Set the system store location in the
	// registry
	L"MY"))                 // Could have used other predefined 
							// system stores
							// including Trust, CA, or Root
{
	printf("Open the MY system store.\n");
}
else
{
	printf("Could not open the MY system store.\n");
	return S_FALSE;
}

//-------------------------------------------------------------------
// Get certificates that have the string represented by wszSmtpAddress 
// in their subject. 

CERT_DATA newestCertData = { 0 };
printf("Looking up your certificate based on the search string you've provided...\n");
if SUCCEEDED(HrCertFindCertificateInStoreBySubject(hSystemStore, NULL, &pOffsetCert, wszSmtpAddress))
{
	memcpy(&pNewestCert, &pOffsetCert, sizeof(PCCERT_CONTEXT));

	do
	{
		hr = HrCertFindCertificateInStoreBySubject(hSystemStore, pOffsetCert, &pNewCert, wszSmtpAddress);
		if (S_OK == hr)
		{
			//lpSysTime = SYSTEMTIME();
			//converted = FileTimeToSystemTime(&pNewCert->pCertInfo->NotAfter, &lpSysTime);
			if (IsCertNewer(pNewCert->pCertInfo->NotAfter, pNewestCert->pCertInfo->NotAfter))
			{
				memcpy(&pNewestCert, &pNewCert, sizeof(PCCERT_CONTEXT));
			}
		}
		memcpy(&pOffsetCert, &pNewCert, sizeof(PCCERT_CONTEXT));
		//ZeroMemory((LPVOID*)&pNewCert, sizeof(PCCERT_CONTEXT));
	} while (S_OK == hr);
	if (S_OK != hr)
	{

	}
}

if (pNewestCert)
{
	wprintf(L"Certificate found.\n");
	memcpy((VOID*)pCertContext, &pNewestCert, sizeof(PCCERT_CONTEXT));
	return true;
}
else return S_FALSE;

return SUCCEEDED(hr);
}


// Put together the new security profile and return it
// pccSignature = the SMIME signature certificate
// pccEncryption = the SMIME encryption certificate
// wsProfileName = the name of the security profile as displayed by Outloolk
// bDefaultProfile = indicates whether this should be saved as the default SMIME security profile
// Default hash algorithm
// lpProfile = the returned payload
HRESULT NewSecurityProfile(DWORD cbSignHash, LPBYTE lpbSignHash, DWORD cbEncHash, LPBYTE lpbEncHash, std::wstring wsProfileName, bool bDefaultProfile, std::string szDefaultSignatureHashOID, LPSBinary lpProfile)
{
	HRESULT hRes = S_OK;
	ULONG cCertContext = 0;

	CRYPT_SMIME_CAPABILITY capAES256 = { szOID_NIST_AES256_CBC, 0, nullptr };
	CRYPT_SMIME_CAPABILITY capAES192 = { szOID_NIST_AES192_CBC, 0, nullptr };
	CRYPT_SMIME_CAPABILITY capAES128 = { szOID_NIST_AES128_CBC, 0, nullptr };

	// Set up the SMIME Caps with the default order
	std::vector<CRYPT_SMIME_CAPABILITY> vSMIMECapabilites {
		{ szOID_NIST_sha256, 0, nullptr },
		{ szOID_NIST_sha384, 0, nullptr },
		{ szOID_NIST_sha512, 0, nullptr },
	};

	if (szDefaultSignatureHashOID.length() > 0) {
		// The user has specified a preference
		// Capture the preference hashing alg, and sort the vector accordingly
		std::sort(vSMIMECapabilites.begin(), vSMIMECapabilites.end(), [szDefaultSignatureHashOID](CRYPT_SMIME_CAPABILITY cap1, CRYPT_SMIME_CAPABILITY cap2) -> bool {
			// The selected default OID always takes precedence
			if (cap1.pszObjId == szDefaultSignatureHashOID) {
				return true;
			}
			else if (cap2.pszObjId == szDefaultSignatureHashOID) {
				return false;
			}
			// from there, just follow the original ordering
			else if (cap1.pszObjId == szOID_NIST_sha256 && (cap2.pszObjId == szOID_NIST_sha384 || cap2.pszObjId == szOID_NIST_sha512)) {
				return true;
			}
			else if (cap1.pszObjId == szOID_NIST_sha384 && cap2.pszObjId == szOID_NIST_sha256) {
				return false;
			}
			else if (cap1.pszObjId == szOID_NIST_sha384 && cap2.pszObjId == szOID_NIST_sha512) {
				return true;
			}
			else if (cap1.pszObjId == szOID_NIST_sha512 && (cap2.pszObjId == szOID_NIST_sha256 || cap2.pszObjId == szOID_NIST_sha384)) {
				return false;
			}
			return false;
		});
	}

	// Now that the hashing algs are sorted, go ahead and add the encryption algs
	vSMIMECapabilites.push_back(capAES256);
	vSMIMECapabilites.push_back(capAES192);
	vSMIMECapabilites.push_back(capAES128);

	//Generate an ASN1-encoded S/MIME capabilities binary large object (BLOB)
	CRYPT_SMIME_CAPABILITIES Capabilities;
	ZeroMemory(&Capabilities, sizeof(Capabilities));
	Capabilities.cCapability = vSMIMECapabilites.size();
	Capabilities.rgCapability = vSMIMECapabilites.data();

	DWORD cbEncoded;		// variable to hold the length of the encoded object
	BYTE * pbEncoded;		// variable to hold a pointer to the encoded buffer

							// Convert the profile name to Ansi for convenience
	std::string szProfileName;
	szProfileName.assign(wsProfileName.begin(), wsProfileName.end());

	// Call it with a NULL pbEncoded to get the buffer size
	EC_BOOL(CryptEncodeObject(
		X509_ASN_ENCODING,        // the encoding/decoding type
		PKCS_SMIME_CAPABILITIES,
		&Capabilities,
		NULL,
		&cbEncoded));

	EC_BOOL(pbEncoded = (BYTE*)malloc(cbEncoded));

	// Now that we have pbEncoded, call CryptEncodeObject
	EC_BOOL(CryptEncodeObject(
		X509_ASN_ENCODING,        // the encoding/decoding type
		PKCS_SMIME_CAPABILITIES,
		&Capabilities,
		pbEncoded,
		&cbEncoded));

	// Allocate memory for the structure we will be using for putting the data together
	LPSSECPROF sSecProf = new _SSecProf();
	ZeroMemory(sSecProf, sizeof(_SSecProf));
	wprintf(L"Assembling the new security profile data...\n");
	// PR_CERT_PROP_VERSION
	sSecProf->certPropVersionTag = 0x0001;//GetWord(PR_CERT_PROP_VERSION);
	sSecProf->certPropVersionSize = sizeof(DWORD) + sizeof(LONG);
	sSecProf->certPropVersionValue = 1;

	// PR_CERT_MESSAGE_ENCODING
	sSecProf->certMessageEncodingTag = 0x0006; //GetWord(PR_CERT_MESSAGE_ENCODING);
	sSecProf->certMessageEncodingSize = sizeof(DWORD) + sizeof(LONG);
	sSecProf->certMessageEncodingValue = 1;

	// PR_CERT_DEFAULTS
	sSecProf->certDefaultsTag = 0x0020;// GetWord(PR_CERT_DEFAULTS);
	sSecProf->certDefaultsSize = sizeof(DWORD) + sizeof(LONG);
	if (bDefaultProfile)
	{
		sSecProf->certDefaultsValue = MSG_DEFAULTS_FOR_FORMAT | MSG_DEFAULTS_GLOBAL | MSG_DEFAULTS_SEND_CERT;
	}
	else
	{
		sSecProf->certDefaultsValue = MSG_DEFAULTS_SEND_CERT;
	}

	// PR_CERT_DISPLAY_NAME_A
	sSecProf->certDisplayNameATag = 0x000B;// GetWord(PR_CERT_DISPLAY_NAME_A);
	sSecProf->certDisplayNameASize = sizeof(DWORD) + (szProfileName.length() +1) * sizeof(char) ;
	sSecProf->certDisplayNameAcb = (szProfileName.length()) * sizeof(char) + sizeof(char); //keeping track of the bytes to copy here rather than the overall property size
	sSecProf->certDisplayNameAValue = (LPSTR)szProfileName.c_str();

	// PR_CERT_DISPLAY_NAME_W
	sSecProf->certDisplayNameWTag = 0x0051; //GetWord(PR_CERT_DISPLAY_NAME_W);
	sSecProf->certDisplayNameWSize = (wsProfileName.length() + 1) * sizeof(wchar_t) + sizeof(WORD) * 2;
	sSecProf->certDisplayNameWcb = (wsProfileName.length() + 1) * sizeof(wchar_t);
	sSecProf->certDisplayNameWValue = LPWSTR(wsProfileName.c_str());

	// PR_CERT_KEYEX_SHA1_HASH
	sSecProf->certKeyexSha1Tag = 0x0022; // GetWord(PR_CERT_KEYEX_SHA1_HASH);
	sSecProf->certKeyexSha1Size = sizeof(DWORD) + cbEncHash;
	sSecProf->certKeyexSha1cb = cbEncHash;
	sSecProf->certKeyexSha1lpb = lpbEncHash;

	// PR_CERT_SIGN_SHA1_HASH
	sSecProf->certSignSha1Tag = 0x0009; //GetWord(PR_CERT_SIGN_SHA1_HASH);
	sSecProf->certSignSha1Size = sizeof(DWORD) + cbSignHash;;
	sSecProf->certSignSha1cb = cbSignHash;
	sSecProf->certSignSha1lpb = lpbSignHash;

	// PR_CERT_ASYMETRIC_CAPS
	sSecProf->certAsymetricCapsTag = 0x0002; // GetWord(PR_CERT_ASYMETRIC_CAPS);
	sSecProf->certAsymetricCapsSize = sizeof(DWORD) + cbEncoded;;
	sSecProf->certAsymetricCapscb = (WORD)cbEncoded;
	sSecProf->certAsymetricCapslpb = pbEncoded;

	// Assemble the byte array representation of the security profile
	int bytecount = sSecProf->certPropVersionSize
		+ sSecProf->certMessageEncodingSize
		+ sSecProf->certDefaultsSize
		+ sSecProf->certDisplayNameASize
		+ sSecProf->certDisplayNameWSize
		+ sSecProf->certKeyexSha1Size
		+ sSecProf->certSignSha1Size
		+ sSecProf->certAsymetricCapsSize;

	// allocate memory for it
	byte * secProf = (byte*)malloc(bytecount);
	ZeroMemory(secProf, bytecount);

	// Just to keep track of where we are
	int pos = 0;

	// Coppy the data into the byte array
	memcpy(&secProf[pos], &sSecProf->certPropVersionTag, sizeof(sSecProf->certPropVersionTag));
	pos += sizeof(sSecProf->certPropVersionTag);
	memcpy(&secProf[pos], &sSecProf->certPropVersionSize, sizeof(sSecProf->certPropVersionSize));
	pos += sizeof(sSecProf->certPropVersionSize);
	memcpy(&secProf[pos], &sSecProf->certPropVersionValue, sizeof(sSecProf->certPropVersionValue));
	pos += sizeof(sSecProf->certPropVersionValue);

	memcpy(&secProf[pos], &sSecProf->certMessageEncodingTag, sizeof(sSecProf->certMessageEncodingTag));
	pos += sizeof(sSecProf->certMessageEncodingTag);
	memcpy(&secProf[pos], &sSecProf->certMessageEncodingSize, sizeof(sSecProf->certMessageEncodingSize));
	pos += sizeof(sSecProf->certMessageEncodingSize);
	memcpy(&secProf[pos], &sSecProf->certMessageEncodingValue, sizeof(sSecProf->certMessageEncodingValue));
	pos += sizeof(sSecProf->certMessageEncodingValue);

	memcpy(&secProf[pos], &sSecProf->certDefaultsTag, sizeof(sSecProf->certDefaultsTag));
	pos += sizeof(sSecProf->certDefaultsTag);
	memcpy(&secProf[pos], &sSecProf->certDefaultsSize, sizeof(sSecProf->certDefaultsSize));
	pos += sizeof(sSecProf->certDefaultsSize);
	memcpy(&secProf[pos], &sSecProf->certDefaultsValue, sizeof(sSecProf->certDefaultsValue));
	pos += sizeof(sSecProf->certDefaultsValue);

	memcpy(&secProf[pos], &sSecProf->certDisplayNameWTag, sizeof(sSecProf->certDisplayNameWTag));
	pos += sizeof(sSecProf->certDisplayNameWTag);
	memcpy(&secProf[pos], &sSecProf->certDisplayNameWSize, sizeof(sSecProf->certDisplayNameWSize));
	pos += sizeof(sSecProf->certDisplayNameWSize);
	memcpy(&secProf[pos], sSecProf->certDisplayNameWValue, sSecProf->certDisplayNameWcb);
	pos += sSecProf->certDisplayNameWcb;

	memcpy(&secProf[pos], &sSecProf->certDisplayNameATag, sizeof(sSecProf->certDisplayNameATag));
	pos += sizeof(sSecProf->certDisplayNameATag);
	memcpy(&secProf[pos], &sSecProf->certDisplayNameASize, sizeof(sSecProf->certDisplayNameASize));
	pos += sizeof(sSecProf->certDisplayNameASize);
	memcpy(&secProf[pos], sSecProf->certDisplayNameAValue, sSecProf->certDisplayNameAcb);
	pos += sSecProf->certDisplayNameAcb;

	memcpy(&secProf[pos], &sSecProf->certSignSha1Tag, sizeof(sSecProf->certSignSha1Tag));
	pos += sizeof(sSecProf->certSignSha1Tag);
	memcpy(&secProf[pos], &sSecProf->certSignSha1Size, sizeof(sSecProf->certSignSha1Size));
	pos += sizeof(sSecProf->certKeyexSha1Size);
	memcpy(&secProf[pos], sSecProf->certSignSha1lpb, sSecProf->certSignSha1cb);
	pos += sSecProf->certSignSha1cb;

	memcpy(&secProf[pos], &sSecProf->certKeyexSha1Tag, sizeof(sSecProf->certKeyexSha1Tag));
	pos += sizeof(sSecProf->certKeyexSha1Tag);
	memcpy(&secProf[pos], &sSecProf->certKeyexSha1Size, sizeof(sSecProf->certKeyexSha1Size));
	pos += sizeof(sSecProf->certKeyexSha1Size);
	memcpy(&secProf[pos], sSecProf->certKeyexSha1lpb, sSecProf->certKeyexSha1cb);
	pos += sSecProf->certKeyexSha1cb;

	memcpy(&secProf[pos], &sSecProf->certAsymetricCapsTag, sizeof(sSecProf->certAsymetricCapsTag));
	pos += sizeof(sSecProf->certAsymetricCapsTag);
	memcpy(&secProf[pos], &sSecProf->certAsymetricCapsSize, sizeof(sSecProf->certAsymetricCapsSize));
	pos += sizeof(sSecProf->certAsymetricCapsSize);
	memcpy(&secProf[pos], sSecProf->certAsymetricCapslpb, sSecProf->certAsymetricCapscb);

	// copy the resulting array in lpbProfile
	lpProfile->cb = bytecount;
	lpProfile->lpb = secProf;
	//memcpy(lpProfile->lpb, secProf, bytecount);
	if (sSecProf) MAPIFreeBuffer(sSecProf);
Error:
	goto Cleanup;
Cleanup:
	
	return hRes;
}

void MakeSecondary(DWORD cbIn, IN OUT LPBYTE pbIn)
{
	LONG                cb;
	DWORD               cbData;
	DWORD               cval;
	LPSSecPropValueRead		p;
	LPBYTE              pb;
	SSecPropValue *     pval = NULL;

	cval = 0;
	for (cb = cbIn, pb = pbIn, cbData = 0; cb > 0; cval++) {
		// Check that we're not reading past the end of the buffer
		p = (LPSSecPropValueRead)pb;

		// Check for wSize less than 4 since 4 is the size of the structure; only happens when data is improperly encoded
		/*if (p->wSize < sizeof(SSecPropValue))
		goto Error;*/
		std::wstring tempsz = L"";
		switch (GetWord(&(p->wTag)))
		{
		case PROP_ID(PR_CERT_DEFAULTS):
			if (p->Value.l || MSG_DEFAULTS_FOR_FORMAT)
			{
				p->Value.l = MSG_DEFAULTS_SEND_CERT;
			}
			break;
		default:
			break;
		}
		cb -= GetWord(&(p->wSize));
		pb += GetWord(&(p->wSize));
	}
}
// Writes the new security profile in the PR_SECURITY_PROFILES property
HRESULT SaveSecurityProfile(LPMAPISESSION lpSession, LPSBinary lpProfile, bool bOverwrite, bool bDefaultProfile)
{
	HRESULT hr = S_OK;
	LPPROFSECT lpProfSect = NULL;

	// Access the Dilkie profile section
	lpSession->OpenProfileSection((LPMAPIUID)&GUID_Dilkie, NULL, MAPI_MODIFY | MAPI_FORCE_ACCESS, &lpProfSect);

	if (lpProfSect)
	{
		// Get an IMAPIProp interface pointer for the profile section
		LPMAPIPROP lpMapiProp = NULL;
		lpProfSect->QueryInterface(IID_IMAPIProp, (LPVOID*)&lpMapiProp);

		if (lpMapiProp)
		{
			LPSPropValue lpPrSecProf = NULL;

			if (bOverwrite)
			{
				// Allocate memory for the new property value
				MAPIAllocateBuffer(sizeof(SPropValue), (LPVOID *)&lpPrSecProf);
				ZeroMemory(lpPrSecProf, sizeof(SPropValue));

				lpPrSecProf->ulPropTag = PR_SECURITY_PROFILES;
				lpPrSecProf->Value.MVbin.cValues = 1;
				lpPrSecProf->Value.MVbin.lpbin = new SBinary();
				lpPrSecProf->Value.MVbin.lpbin[0].cb = lpProfile->cb;
				lpPrSecProf->Value.MVbin.lpbin[0].lpb = lpProfile->lpb;

				wprintf(L"Overwriting existing security profiles...\n");
				// Save the new proroperty value
				EC_HR(lpProfSect->SetProps(1, lpPrSecProf, NULL));

				// Free up memory
				MAPIFreeBuffer(lpPrSecProf);
			}
			else
			{
				// Retrieve the existing security profiles if any
				hr = HrGetOneProp(lpMapiProp, PR_SECURITY_PROFILES, &lpPrSecProf);
				if (S_OK == hr)
				{
					if (lpPrSecProf)
					{
						if (lpPrSecProf->Value.MVbin.cValues > 0)
						{
							// Size of the new security profiles collection
							int newSize = lpPrSecProf->Value.MVbin.cValues + 1;

							// temporary variable to store the new collection
							LPSPropValue lpTempSecProf = NULL;
							// Allocating memory for it
							MAPIAllocateBuffer(sizeof(SPropValue), (LPVOID *)&lpTempSecProf);
							ZeroMemory(lpTempSecProf, sizeof(SPropValue));

							lpTempSecProf->ulPropTag = PR_SECURITY_PROFILES;
							lpTempSecProf->Value.MVbin.cValues = newSize;
							lpTempSecProf->Value.MVbin.lpbin = new SBinary();

							MAPIAllocateBuffer(sizeof(SBinary) * newSize, (LPVOID *)&lpTempSecProf->Value.MVbin.lpbin);
							ZeroMemory(lpTempSecProf->Value.MVbin.lpbin, sizeof(SBinary) * newSize);

							// Copying the existing profiles in the temp variable
							for (int i = 0; i < newSize - 1; i++)
							{
								lpTempSecProf->Value.MVbin.lpbin[i].cb = lpPrSecProf->Value.MVbin.lpbin[i].cb;
								if (bDefaultProfile)
									MakeSecondary(lpPrSecProf->Value.MVbin.lpbin[i].cb, lpPrSecProf->Value.MVbin.lpbin[i].lpb);

								lpTempSecProf->Value.MVbin.lpbin[i].lpb = lpPrSecProf->Value.MVbin.lpbin[i].lpb;

							}

							// Adding the new profile at the very end
							lpTempSecProf->Value.MVbin.lpbin[newSize - 1].cb = lpProfile->cb;
							lpTempSecProf->Value.MVbin.lpbin[newSize - 1].lpb = lpProfile->lpb;

							wprintf(L"Writing the updated security profiles collection...\n");
							EC_HR(lpProfSect->SetProps(1, lpTempSecProf, NULL));

							// Free up memory
							MAPIFreeBuffer(lpTempSecProf);
						}
						else
						{
							// Allocate memory for the new property value
							MAPIAllocateBuffer(sizeof(SPropValue), (LPVOID *)&lpPrSecProf);
							ZeroMemory(lpPrSecProf, sizeof(SPropValue));

							lpPrSecProf->ulPropTag = PR_SECURITY_PROFILES;
							lpPrSecProf->Value.MVbin.cValues = 1;
							lpPrSecProf->Value.MVbin.lpbin = new SBinary();
							lpPrSecProf->Value.MVbin.lpbin[0].cb = lpProfile->cb;
							lpPrSecProf->Value.MVbin.lpbin[0].lpb = lpProfile->lpb;

							wprintf(L"Writing new security profile...\n");
							// Save the new proroperty value
							EC_HR(lpProfSect->SetProps(1, lpPrSecProf, NULL));

							// Free up memory
							MAPIFreeBuffer(lpPrSecProf);
						}
						// Free up memory
						MAPIFreeBuffer(lpPrSecProf);
					}
				}
				else if (MAPI_E_NOT_FOUND == hr)
				{
					// Allocate memory for the new property value
					MAPIAllocateBuffer(sizeof(SPropValue), (LPVOID *)&lpPrSecProf);
					ZeroMemory(lpPrSecProf, sizeof(SPropValue));

					lpPrSecProf->ulPropTag = PR_SECURITY_PROFILES;
					lpPrSecProf->Value.MVbin.cValues = 1;
					lpPrSecProf->Value.MVbin.lpbin = new SBinary();
					lpPrSecProf->Value.MVbin.lpbin[0].cb = lpProfile->cb;
					lpPrSecProf->Value.MVbin.lpbin[0].lpb = lpProfile->lpb;

					wprintf(L"Overwriting existing security profiles...\n");
					// Save the new proroperty value
					EC_HR(lpProfSect->SetProps(1, lpPrSecProf, NULL));

					// Free up memory
					MAPIFreeBuffer(lpPrSecProf);
				}
				else
					EC_HR(hr);
			}
			// Release the IMAPIProp interface pointer
			lpMapiProp->Release();
		}
		// Release the profile section pointer
		lpProfSect->Release();
	}

Error:
	goto Cleanup;
Cleanup:
	return hr;
}

// Writes the new security profile in the PR_SECURITY_PROFILES property
HRESULT ClearSecurityProfiles(LPMAPISESSION lpSession)
{
	HRESULT hr = S_OK;
	LPPROFSECT lpProfSect = NULL;

	// Access the Dilkie profile section
	lpSession->OpenProfileSection((LPMAPIUID)&GUID_Dilkie, NULL, MAPI_MODIFY | MAPI_FORCE_ACCESS, &lpProfSect);

	if (lpProfSect)
	{
		// Get an IMAPIProp interface pointer for the profile section
		LPMAPIPROP lpMapiProp = NULL;
		lpProfSect->QueryInterface(IID_IMAPIProp, (LPVOID*)&lpMapiProp);

		if (lpMapiProp)
		{
			SizedSPropTagArray(1, taga) = { 1, PR_SECURITY_PROFILES };

			wprintf(L"Deleting existing security profiles...\n");
			// Save the new proroperty value
			EC_HR(lpProfSect->DeleteProps((LPSPropTagArray)&taga, NULL));
			
			// Release the IMAPIProp interface pointer
			lpMapiProp->Release();
		}
		// Release the profile section pointer
		lpProfSect->Release();
	}

Error:
	goto Cleanup;
Cleanup:
	return hr;
}

std::wstring ValidateSecurityProfileName(ULONG cSecProfileEntry, SecProfEntry * pSecProfEntry, std::wstring wsSecurityProfileName, int iAttempt)
{
	bool fFound = false;
	if (cSecProfileEntry > 0)
	{
		for (unsigned int i = 0; i < cSecProfileEntry; i++)
		{
			if (wcscmp(pSecProfEntry[i].wsSecurityProfileName.c_str(), wsSecurityProfileName.c_str()) == 0)
			{
				fFound = true;
				break;
			}
		}
		if (fFound)
		{
			wchar_t buffer[10];
			wchar_t val = (wchar_t)iAttempt;
			int intval = (int)val;
			_itow_s(intval, buffer, 16);
			if (iAttempt > 1)
			{
				wsSecurityProfileName = wsSecurityProfileName.substr((size_t)0, (size_t)(wsSecurityProfileName.length() - 3));
			}
			wsSecurityProfileName = wsSecurityProfileName + L"(" + buffer + L")";
			iAttempt++;
			wsSecurityProfileName = ValidateSecurityProfileName(cSecProfileEntry, pSecProfEntry, wsSecurityProfileName, iAttempt);
		}
		else return wsSecurityProfileName;
	}
	return 	wsSecurityProfileName;
}

// lists the existing secuity profiles
HRESULT GetSecurityProfiles(LPMAPISESSION lpSession, SecProfEntry * pSecProfileEntry)
{
	HRESULT hr = S_OK;
	LPPROFSECT lpProfSect = NULL;
	LPBYTE pbIn = NULL;
	DWORD cbIn = NULL;
	LONG                cb;
	DWORD               cbData;
	DWORD               cval;
	LPSSecPropValueRead		p;
	LPBYTE              pb;
	SSecPropValue *     pval = NULL;

	lpSession->OpenProfileSection((LPMAPIUID)&GUID_Dilkie, NULL, MAPI_MODIFY | MAPI_FORCE_ACCESS, &lpProfSect);
	if (lpProfSect)
	{
		LPMAPIPROP lpMapiProp = NULL;
		lpProfSect->QueryInterface(IID_IMAPIProp, (LPVOID*)&lpMapiProp);
		if (lpMapiProp)
		{
			LPSPropValue prSecProf = NULL;
			hr = HrGetOneProp(lpMapiProp, PR_SECURITY_PROFILES, &prSecProf);
			if (hr == S_OK)
			{
				if (prSecProf->Value.MVbin.cValues > 0)
				{

					for (unsigned int i = 0; i < prSecProf->Value.MVbin.cValues; i++)
					{
						LPBYTE pbIn = prSecProf->Value.MVbin.lpbin[i].lpb;
						DWORD cbIn = prSecProf->Value.MVbin.lpbin[i].cb;

						//
						//  Compute needed size for the data
						//

						cval = 0;
						for (cb = cbIn, pb = pbIn, cbData = 0; cb > 0; cval++) {
							// Check that we're not reading past the end of the buffer
							p = (LPSSecPropValueRead)pb;

							// Check for wSize less than 4 since 4 is the size of the structure; only happens when data is improperly encoded
							/*if (p->wSize < sizeof(SSecPropValue))
							goto Error;*/
							std::wstring tempsz = L"";
							switch (GetWord(&(p->wTag)))
							{
							case PROP_ID(PR_CERT_PROP_VERSION):

								pSecProfileEntry[i].ulCertPropVersion = p->Value.l;
								break;
							case PROP_ID(PR_CERT_MESSAGE_ENCODING):
								pSecProfileEntry[i].ulMessageEncoding = p->Value.l;
								break;
							case PROP_ID(PR_CERT_DEFAULTS):
								pSecProfileEntry[i].ulCertDefaults = p->Value.l;
								break;
							case PROP_ID(PR_CERT_DISPLAY_NAME_A):
								//pSecProfEntry[cval].sSecurityProfileName = BinToHexWString(p->Value.bytes, p->wSize - 4, true, false);
								break;
							case PROP_ID(PR_CERT_DISPLAY_NAME_W):
								pSecProfileEntry[i].wsSecurityProfileName = BinToHexWString(p->Value.bytes, p->wSize - 4, false, false);
								break;
							case PROP_ID(PR_CERT_KEYEX_SHA1_HASH):
								pSecProfileEntry[i].wsEncryptionCertificateHash = BinToHexWString(p->Value.bytes, p->wSize - 4, true, true);
								break;
							case PROP_ID(PR_CERT_SIGN_SHA1_HASH):
								pSecProfileEntry[i].wsSignatureCertificateHash = BinToHexWString(p->Value.bytes, p->wSize - 4, true, true);
								break;
							default:
								cbData += GetWord(&(p->wSize)) - sizeof(SSecPropValue);
								break;
							}
							cb -= GetWord(&(p->wSize));
							pb += GetWord(&(p->wSize));
						}
					}
				}
			}
			else if (hr == MAPI_E_NOT_FOUND)
			{
				wprintf(L"No existing security profiles found");
			}
			else
				EC_HR(hr);
		}
	}

Error:
	goto Cleanup;
Cleanup:
	return hr;
}

// lists the existing secuity profiles
HRESULT GetSecurityProfileCount(LPMAPISESSION lpSession, ULONG * cSecProfileEntry)
{
	HRESULT hr = S_OK;
	LPPROFSECT lpProfSect = NULL;

	lpSession->OpenProfileSection((LPMAPIUID)&GUID_Dilkie, NULL, MAPI_MODIFY | MAPI_FORCE_ACCESS, &lpProfSect);
	if (lpProfSect)
	{
		LPMAPIPROP lpMapiProp = NULL;
		lpProfSect->QueryInterface(IID_IMAPIProp, (LPVOID*)&lpMapiProp);
		if (lpMapiProp)
		{
			LPSPropValue prSecProf = NULL;
			HrGetOneProp(lpMapiProp, PR_SECURITY_PROFILES, &prSecProf);
			if (prSecProf)
			{
				*cSecProfileEntry = prSecProf->Value.MVbin.cValues;
				MAPIFreeBuffer(prSecProf);
			}
			lpMapiProp->Release();
		}
		lpProfSect->Release();
	}

	return hr;
}

void ListSecurityProfiles(ULONG cSecProfileEntry, SecProfEntry * pSecProfileEntry)
{
	for (unsigned int i = 0; i < cSecProfileEntry; i++)
	{
		wprintf(L"Listing security profile #%i\n", i + 1);
		wprintf(L"PropTag: PR_CERT_PROP_VERSION, Value: %i\n", pSecProfileEntry[i].ulCertPropVersion);
		wprintf(L"PropTag: PR_CERT_MESSAGE_ENCODING, Value: %i\n", pSecProfileEntry[i].ulMessageEncoding);
		wprintf(L"PropTag: PR_CERT_DEFAULTS, Value: %i\n", pSecProfileEntry[i].ulCertDefaults);
		//wprintf(L"PropTag: PR_CERT_DISPLAY_NAME_A, PropSize: %i, Value: %ls\n", p->wSize, (LPWSTR)BinToHexWString(p->Value.bytes, p->wSize - 4, true, false).c_str());
		wprintf(L"PropTag: PR_CERT_DISPLAY_NAME_W, Value: %ls\n", (LPWSTR)pSecProfileEntry[i].wsSecurityProfileName.c_str());
		wprintf(L"PropTag: PR_CERT_KEYEX_SHA1_HASH, Value: %ls\n", (LPWSTR)pSecProfileEntry[i].wsEncryptionCertificateHash.c_str());
		wprintf(L"PropTag: PR_CERT_SIGN_SHA1_HASH, Value: %ls\n", (LPWSTR)pSecProfileEntry[i].wsSignatureCertificateHash.c_str());
	}
}

// Retrieve the first certificate that matches the input subject and key usage
HRESULT HrCertFindCertificateInStoreBySubject(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, _Out_ PCCERT_CONTEXT * ppNextCert, std::wstring wszLookupString, ULONG ulKeyUsage)
{
	PCCERT_CONTEXT pCertContext = NULL;

	pCertContext = CertFindCertificateInStore(
		hCertStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		(void *)wszLookupString.c_str(),
		pPrevCert);


	if (pCertContext)
	{
		if (IsRightCertUsage(pCertContext, ulKeyUsage))
		{
			//*ppNextCert = pCertContext;
			*ppNextCert = pCertContext;
			return S_OK;
		}
		else
		{
			return HrCertFindCertificateInStoreBySubject(hCertStore, pCertContext, ppNextCert, wszLookupString, ulKeyUsage);
		}
	}
	else
	{
		return GetLastError();
	}
}


// Retrieve a certificate that matches the input subject
HRESULT HrCertFindCertificateInStoreBySubject(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, PCCERT_CONTEXT * ppNextCert, std::wstring wszLookupString)
{
	PCCERT_CONTEXT pCertContext = NULL;
	MAPIAllocateBuffer(sizeof(PCCERT_CONTEXT),
		(LPVOID*)pCertContext);
	MAPIAllocateBuffer(sizeof(PCCERT_CONTEXT),
		(LPVOID*)ppNextCert);
	pCertContext = CertFindCertificateInStore(
		hCertStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		(void *)wszLookupString.c_str(),
		pPrevCert);

	if (pCertContext)
	{
		//*ppNextCert = pCertContext;
		memcpy(ppNextCert, &pCertContext, sizeof(PCCERT_CONTEXT));
		return S_OK;
	}
	else
	{
		return GetLastError();
	}
}

// Retrieve a certificate that matches the input certificate hash 
HRESULT HrCertFindCertificateInStoreByHash(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCert, PCCERT_CONTEXT * ppNextCert, DWORD cb, LPBYTE lpb)
{
	PCCERT_CONTEXT pCertContext = NULL;
	MAPIAllocateBuffer(sizeof(PCCERT_CONTEXT),
		(LPVOID*)pCertContext);
	MAPIAllocateBuffer(sizeof(PCCERT_CONTEXT),
		(LPVOID*)ppNextCert);

	_CRYPTOAPI_BLOB crytptopApiBlob = { 0 };
	crytptopApiBlob.cbData = cb;
	crytptopApiBlob.pbData = lpb;
	pCertContext = CertFindCertificateInStore(
		hCertStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SHA1_HASH,
		(void *)&crytptopApiBlob,
		pPrevCert);

	if (pCertContext)
	{
		memcpy(ppNextCert, &pCertContext, sizeof(PCCERT_CONTEXT));
		return S_OK;
	}
	else
	{
		return GetLastError();
	}
}

// returns true if the 1st certificate is newer than the second 
BOOL IsCertNewer(FILETIME ftFirstCert, FILETIME ftSecondCert)
{
	ULARGE_INTEGER ulIntFirstCertTime, ulIntSecondCertTime = { 0 };

	ulIntFirstCertTime.HighPart = ftFirstCert.dwHighDateTime;
	ulIntFirstCertTime.LowPart = ftFirstCert.dwLowDateTime;

	ulIntSecondCertTime.HighPart = ftSecondCert.dwHighDateTime;
	ulIntSecondCertTime.LowPart = ftSecondCert.dwLowDateTime;

	ULONGLONG delta = ulIntSecondCertTime.QuadPart - ulIntFirstCertTime.QuadPart;
	signed long long slFirst, slSecond;
	slFirst = (signed long long)ulIntFirstCertTime.QuadPart;
	slSecond = (signed long long)ulIntSecondCertTime.QuadPart;
	if ((slFirst - slSecond) > 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}