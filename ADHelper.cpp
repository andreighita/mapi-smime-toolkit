#include "stdafx.h"
#include "ADHelper.h"

std::wstring GetUserDn()
{
	std::wstring wszUserDn = L"";
	HRESULT hr = S_OK;

	IADsADSystemInfo *pADsys;
	EC_HR(CoCreateInstance(CLSID_ADSystemInfo,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IADsADSystemInfo,
		(void**)&pADsys));

	if (pADsys)
	{
		BSTR bstrUserName = NULL;
		EC_HR(pADsys->get_UserName(&bstrUserName));
		if (bstrUserName)
		{
			wszUserDn = std::wstring(bstrUserName);
			::SysFreeString(bstrUserName);
		}
		pADsys->Release();
	}
Error:
	goto Cleanup;
Cleanup:
	return wszUserDn;
}

std::wstring FindPrimarySMTPAddress(std::wstring wszUserDn)
{

	std::wstring wszSmtpAddress = L"";

	//Intialize COM



	HRESULT hr = S_OK;

	//Get rootDSE and the config container's DN.

	LPADS lpAds = NULL;

	wszUserDn = L"LDAP://" + wszUserDn;
	hr = ADsOpenObject((LPCWSTR)wszUserDn.c_str(),
		NULL,
		NULL,
		ADS_SECURE_AUTHENTICATION,
		//Use Secure Authentication
		IID_IADs,
		(void**)&lpAds);

	if ((S_OK == hr) && lpAds)
	{

		VARIANT varPropValue;
		BSTR bstrProperty = BSTR(L"proxyAddresses");
		hr = lpAds->Get(bstrProperty, &varPropValue);
		if ((SUCCEEDED(hr)) && (VT_VARIANT ^ varPropValue.vt))
		{
			LONG cElements, lLBound, lUBound;

			if (SafeArrayGetDim(varPropValue.parray) == 1)
			{
				// Get array bounds.
				hr = SafeArrayGetLBound(varPropValue.parray, 1, &lLBound);
				if (FAILED(hr))
					goto Error;
				hr = SafeArrayGetUBound(varPropValue.parray, 1, &lUBound);
				if (FAILED(hr))
					goto Error;

				cElements = lUBound - lLBound + 1;

				VARIANT propVal;
				VariantInit(&propVal);
				for (LONG i = 0; i < cElements - 1; i++)
				{
					hr = SafeArrayGetElement(varPropValue.parray, &i, &propVal);
					if (propVal.vt == VT_BSTR)
					{
						std::wstring wszAddress = std::wstring(propVal.bstrVal);
						size_t pos = wszAddress.find(L"SMTP:");
						if (pos != std::wstring::npos)
						{
							pos = wszAddress.find(L":");
							wszSmtpAddress = wszAddress.substr(pos + 1);
							break;
						}
					}
				}


			}
		}
		lpAds->Release();
	}
Error:
	goto Cleanup;
Cleanup:
	return wszSmtpAddress;
}

void FetchUserCertificates(std::wstring wszUserDn)
{
	std::wstring wszSmtpAddress = L"";

	//Intialize COM
	   
	HRESULT hr = S_OK;

	//Get rootDSE and the config container's DN.

	LPADS lpAds = NULL;

	wszUserDn = L"LDAP://" + wszUserDn;
	hr = ADsOpenObject((LPCWSTR)wszUserDn.c_str(),
		NULL,
		NULL,
		ADS_SECURE_AUTHENTICATION,
		//Use Secure Authentication
		IID_IADs,
		(void**)&lpAds);

	if ((S_OK == hr) && lpAds)
	{

		VARIANT varPropValue;
		BSTR bstrProperty = BSTR(L"userCertificate");
		hr = lpAds->Get(bstrProperty, &varPropValue);
		if ((SUCCEEDED(hr)) && (VT_VARIANT ^ varPropValue.vt))
		{
			LONG cElements, lLBound, lUBound;

			if (SafeArrayGetDim(varPropValue.parray) == 1)
			{
				// Get array bounds.
				hr = SafeArrayGetLBound(varPropValue.parray, 1, &lLBound);
				if (FAILED(hr))
					goto Error;
				hr = SafeArrayGetUBound(varPropValue.parray, 1, &lUBound);
				if (FAILED(hr))
					goto Error;

				cElements = lUBound - lLBound + 1;

				VARIANT propVal;
				VariantInit(&propVal);
				for (LONG i = 0; i < cElements - 1; i++)
				{
					hr = SafeArrayGetElement(varPropValue.parray, &i, &propVal);
					if (propVal.vt == VT_ARRAY)
					{

						// here we wanna read the propval and see how we parse it 

						/*std::wstring wszAddress = std::wstring(propVal.bstrVal);
						size_t pos = wszAddress.find(L"SMTP:");
						if (pos != std::wstring::npos)
						{
							pos = wszAddress.find(L":");
							wszSmtpAddress = wszAddress.substr(pos + 1);
							break;
						}*/
					}
				}


			}
		}
		lpAds->Release();
	}
Error:
	goto Cleanup;
Cleanup:
	return;
}




void FetchADCertificate()
{
	HCERTSTORE     hStore = NULL;

	PCCERT_CONTEXT pCertCtx = NULL;

	WCHAR          wszDN[MAXBUFF];
	ULONG          cchDN = MAXBUFF;

	WCHAR          wszQuery[MAXBUFF * 2];
	ULONG          cchQuery = MAXBUFF * 2;

	//  Determine the name of the user whose certificate is being
	//  retrieved. This value can be constructed by other means,
	//  but this example will use GetUserNameEx.
	if (!GetUserNameEx(NameFullyQualifiedDN,
		wszDN,
		&cchDN))
	{
		printf("Failed GetUserNameEx: %x\n",
			GetLastError());
		exit(1);
	}

	//  Build the LDAP query string.
	if (S_OK != StringCchPrintf(wszQuery,
		cchQuery,
		L"ldap:///%s?%s",
		wszDN,
		L"userCertificate"))
	{
		printf("Failed StringCchPrintf\n");
		exit(1);

	}

	//  Open the Active Directory certificate store.
	hStore = CertOpenStore(CERT_STORE_PROV_LDAP,
		0,
		0,
		CERT_STORE_READONLY_FLAG,
		wszQuery);
	if (NULL == hStore)
	{
		printf("Failed CertOpenStore - %x\n", GetLastError());
		exit(1);
	}

	//  Retrieve a certificate context from this opened store.
	//  Here, retrieve any existing certificate stored for 
	//  the user in Active Directory.
	//  If more than one certificate exists, consult
	//  CertFindCertificateInStore documentation for search 
	//  types and calling instructions.
	pCertCtx = CertFindCertificateInStore(hStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_FIND_ANY,
		NULL,
		NULL);
	if (NULL == pCertCtx)
	{
		DWORD dwErr;
		dwErr = GetLastError();
		if (CRYPT_E_NOT_FOUND == dwErr)
			printf("User does not have certificate"
				"in Active Directory\n");
		else
			printf("Failed CertFindCertificateInStore - %x\n",
				dwErr);
	}
	else
	{
		//  Use the certificate context as needed.
		//  Here, display the serial number.
		DWORD dwLen, i;
		dwLen = pCertCtx->pCertInfo->SerialNumber.cbData;
		//  The serial number bytes are stored
		//  least significant byte first.
		printf("Serial number: ");
		for (i = dwLen - 1; i != MAXDWORD; i--)
			printf("%02x",
				*(pCertCtx->pCertInfo->SerialNumber.pbData + i));
		printf("\n");
		//  Free the certificate context.
		CertFreeCertificateContext(pCertCtx);
	}

	//  Close the certificate store.
	CertCloseStore(hStore, 0);

}