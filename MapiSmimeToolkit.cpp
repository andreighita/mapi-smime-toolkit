﻿// MapiSmimeToolkit.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "RegistryHelper.h"
#include "MapiSmimeToolkit.h"
#include "MapiSession.h"
#include "SecurityProfile.h"


BOOL Is64BitProcess(void)
{
#if defined(_WIN64)
	return TRUE;   // 64-bit program
#else
	return FALSE;
#endif
}

BOOL _cdecl IsCorrectBitness()
{

	std::wstring szOLVer = L"";
	std::wstring szOLBitness = L"";
	szOLVer = GetStringValue(HKEY_CLASSES_ROOT, TEXT("Outlook.Application\\CurVer"), NULL);
	if (szOLVer != L"")
	{
		if (szOLVer == L"Outlook.Application.16")
		{
			szOLBitness = GetStringValue(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Office\\16.0\\Outlook"), TEXT("Bitness"));
			if (szOLBitness != L"")
			{
				if (szOLBitness == L"x64")
				{
					if (Is64BitProcess())
						return TRUE;
				}
				else if (szOLBitness == L"x86")
				{
					if (Is64BitProcess())
						return FALSE;
					else
						return TRUE;
				}
				else return FALSE;
			}
		}
		else if (szOLVer == L"Outlook.Application.15")
		{
			szOLBitness = GetStringValue(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Office\\15.0\\Outlook"), TEXT("Bitness"));
			if (szOLBitness != L"")
			{
				if (szOLBitness == L"x64")
				{
					if (Is64BitProcess())
						return TRUE;
				}
				else if (szOLBitness == L"x86")
				{
					if (Is64BitProcess())
						return FALSE;
					else
						return TRUE;
				}
				else return FALSE;
			}
		}
		else if (szOLVer == L"Outlook.Application.14")
		{
			szOLBitness = GetStringValue(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Office\\14.0\\Outlook"), TEXT("Bitness"));
			if (szOLBitness != L"")
			{
				if (szOLBitness == L"x64")
				{
					if (Is64BitProcess())
						return TRUE;
				}
				else if (szOLBitness == L"x86")
				{
					if (Is64BitProcess())
						return FALSE;
					else
						return TRUE;
				}
				else return FALSE;
			}
		}
		else return FALSE;
		return FALSE;
	}
	else return FALSE;
}

// Parses input arguments
// -s for Sighing cert hash
// -e for encryption cert hash
// -u for e-mail address
// -o for overwrite
// -d for default
// -m for the running mode (1 = edit, 2 = list)
// -p for the Outlook profile name
// -l for listing the profiles
// -c for clearing the profiles. 
BOOL ParseArgs(int argc, _TCHAR* argv[], ToolkitOptions * pToolkitOptions)
{
	if (!pToolkitOptions) return FALSE;

	ZeroMemory(pToolkitOptions, sizeof(ToolkitOptions));

	// Setting running mode to Read as a default
	pToolkitOptions->bOverWrite = false;
	pToolkitOptions->bDefaultSecurityProfule = false;
	pToolkitOptions->bDefaultOutlookProfile = true;
	pToolkitOptions->ulRunningMode = RUNNINGMODE_EDIT;
	pToolkitOptions->ulCertMode = CERTMODE_LOOKUP;

	for (int i = 1; i < argc; i++)
	{
		switch (argv[i][0])
		{
		case '-':
		case '/':
		case '\\':
			if (0 == argv[i][1])
			{
				// Bad argument - get out of here
				return false;
			}
			switch (tolower(argv[i][1]))
			{
			case 'o':
				pToolkitOptions->bOverWrite = true;
				break;
			case 'd':
				pToolkitOptions->bDefaultSecurityProfule = true;
				break;
			case 'p':
				pToolkitOptions->wsOutlookProfileName = argv[i + 1];
				pToolkitOptions->bDefaultOutlookProfile = false;
				i++;
				break;
			case 's':
				pToolkitOptions->wsSigningCertHash = std::wstring(argv[i + 1]);
					i++;
				break;
			case 'e':
				pToolkitOptions->wsEncryptionCertHash = std::wstring(argv[i + 1]);
				i++;
				break;
			case 'u':
				pToolkitOptions->wsEmailAddress = std::wstring(argv[i + 1]);
				i++;
				break;
			case 'l':
				pToolkitOptions->ulRunningMode = RUNNINGMODE_LIST;
				i++;
				break;
			case 'h':
				pToolkitOptions->ulCertMode = CERTMODE_HASH;
				break;
			case 'c':
				pToolkitOptions->ulRunningMode = RUNNINGMODE_CLEAR;
				break;
			default:
				// display help
				return false;
				break;
			}
		}
	}

	// If one of the string properties is missing then return false
	if (RUNNINGMODE_EDIT == pToolkitOptions->ulRunningMode)
	{
		if (pToolkitOptions->wsEmailAddress != L"")
		{
			if ((CERTMODE_HASH == pToolkitOptions->ulCertMode) && ((pToolkitOptions->wsEncryptionCertHash == L"") || (pToolkitOptions->wsSigningCertHash == L"")))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}


	// If no running mode was specified then fail
	if (RUNNINGMODE_UNDEFINED == pToolkitOptions->ulRunningMode)
	{
		return false;
	}

	return true;
}

void DisplayUsage()
{
	printf("MapiSmimeToolkit - Outlook Security Profile toolkit.\n");
	printf("    Allows listing and managing security profiles.\n");
	printf("\n");
	printf("Usage: MapiSmimeToolkit [-s SignatureHash] [-e EncryptionHash] [-u EmailAddress]  \n");
	printf("       [-o] [-d] [-p OutlookProfileName] [-l] [-h] \n");
	printf("\n");
	printf("Options:\n");
	printf("       -s:     The Signature certificate hash (thumbprint)\n");
	printf("       -e:     The Encryption certificate hash (thumbprint)\n");
	printf("       -u:     The user e-mail address to add to the security profile name\n");
	printf("       -p:     The name of the Outlook profile to perform the changes in.\n");
	printf("       	       If this is not specified, the default Outlook profile will be used.\n");
	printf("       -l:     For running the tool in List mode.\n");
	printf("       -h:     Allows specifying the certificate  hashes rather than performing a\n");
	printf("       	       name look-up.\n");
	printf("       -o      Overwrites any existing security profiles.\n");
	printf("       -d      Sets the new security profile as the default profile.\n");
	printf("       -c      Clears (removes) all existing security profiles.\n");
	printf("       -?      Displays this usage information.\n");
}

void _tmain(int argc, _TCHAR* argv[])
{
	if (!IsCorrectBitness())
	{
		wprintf(L"Unable to resolve bitness or bitness not matched.");
		return;
	}
	ToolkitOptions * pToolkitOptions = new ToolkitOptions();
	// Parse the command line arguments
	wprintf(L"Parsing input arguments.\n");
	if (!ParseArgs(argc, argv, pToolkitOptions))
	{
		DisplayUsage();
		return;
	}
	HRESULT hr = S_OK;
	try
	{
		
		wprintf(L"Initializing MAPI.\n");
		EC_HR(CoInitialize(NULL));
		EC_HR(MAPIInitialize(0));

		LPMAPISESSION lpSession = NULL;
		// not allocated memory here !!!!!!!!!!!!!!!!!!!!!!!!
		// !!!!!!!!!!! // #??? 

		ZeroMemory(&lpSession, sizeof(LPMAPISESSION));
		if (!pToolkitOptions->bDefaultOutlookProfile)
		{
			wprintf(L"Logging in to the MAPI subsystem.\n");
			EC_HR(Logon((LPWSTR)pToolkitOptions->wsOutlookProfileName.c_str(), &lpSession));
		}
		else
		{
			wprintf(L"Logging in to the MAPI subsystem.\n");
			EC_HR(Logon(&lpSession));
		}

		ULONG cSecurityProfiles = 0;
		SecProfEntry * pSecProfEntry = NULL;
		wprintf(L"Getting security profile count in current MAPI profile.\n");
		GetSecurityProfileCount(lpSession, &cSecurityProfiles);
		if (cSecurityProfiles > 0)
		{
			MAPIAllocateBuffer(sizeof(SecProfEntry) * cSecurityProfiles, (LPVOID*)&pSecProfEntry);
			ZeroMemory(pSecProfEntry, sizeof(SecProfEntry) * cSecurityProfiles);
			wprintf(L"Fetching security profiles...\n");
			EC_HR(GetSecurityProfiles(lpSession, pSecProfEntry));
		}

		if (RUNNINGMODE_EDIT == pToolkitOptions->ulRunningMode)
		{
			std::wstring wsProfileNAme = L"My S/MIME Settings (" + pToolkitOptions->wsEmailAddress + L")";
			if (!pToolkitOptions->bOverWrite)
			// #??? 
			// something wrong with this logic here for overweriting?

			wprintf(L"Validating new security profile name.\n");
			// #??? this doesn't seem to increment the existing profile crated with Outlook 
			wsProfileNAme = ValidateSecurityProfileName(cSecurityProfiles, pSecProfEntry, wsProfileNAme, 1);
			
			wprintf(L"The name of the new security profile will be %ls\n", (LPWSTR)wsProfileNAme.c_str());
			LPSBinary lpProfile = new SBinary();
			if (CERTMODE_HASH == pToolkitOptions->ulCertMode)
			{
				DWORD cbSignHash = 0;
				LPBYTE lpbSignHash = new BYTE(20);
				DWORD cbEncHash = 0;
				LPBYTE lpbEncHash = new BYTE(20);
				// Making sure the input certificate thumbprints are valid
				wprintf(L"Searching for signature certificate...\n");
				EC_BOOL(FindCertificate(pToolkitOptions->wsSigningCertHash, &cbSignHash, &lpbSignHash));
				wprintf(L"Searching for encryption certificate...\n");
				EC_BOOL(FindCertificate(pToolkitOptions->wsEncryptionCertHash, &cbEncHash, &lpbEncHash));
				if (cbSignHash > 0 && cbEncHash > 0)
				{
					wprintf(L"Creating security profile...\n");
					EC_HR(NewSecurityProfile(cbSignHash, lpbSignHash, cbEncHash, lpbEncHash, wsProfileNAme, pToolkitOptions->bDefaultSecurityProfule, lpProfile));
					if (lpProfile != 0)
					{
						wprintf(L"Saving security profile changes...\n");
						EC_HR(SaveSecurityProfile(lpSession, lpProfile, pToolkitOptions->bOverWrite, pToolkitOptions->bDefaultSecurityProfule));
					}
				}
				else
					wprintf(L"No SMIME certificates found.\n");
			}
			else
			{
				DWORD cbSignHash = 0;
				LPBYTE lpbSignHash = new BYTE(20);
				DWORD cbEncHash = 0;
				LPBYTE lpbEncHash = new BYTE(20);

				wprintf(L"Looking up signature certificate...\n");
				EC_BOOL(CertificateFound(pToolkitOptions->wsEmailAddress, &cbSignHash, &lpbSignHash, CERT_DIGITAL_SIGNATURE_KEY_USAGE));
				wprintf(L"Looking up encryption certificate...\n");
				EC_BOOL(CertificateFound(pToolkitOptions->wsEmailAddress, &cbEncHash, &lpbEncHash, CERT_KEY_ENCIPHERMENT_KEY_USAGE));
				if (cbSignHash > 0 && cbEncHash > 0)
				{
					wprintf(L"Creating security profile...\n");
					EC_HR(NewSecurityProfile(cbSignHash, lpbSignHash, cbEncHash, lpbEncHash, wsProfileNAme, pToolkitOptions->bDefaultSecurityProfule, lpProfile));
					if (lpProfile != 0)
					{
						wprintf(L"Saving security profile changes...\n");
						EC_HR(SaveSecurityProfile(lpSession, lpProfile, pToolkitOptions->bOverWrite, pToolkitOptions->bDefaultSecurityProfule));
					}
				}
				else
					wprintf(L"No SMIME certificates found.\n");
			}


		}
		else if ((RUNNINGMODE_LIST == pToolkitOptions->ulRunningMode) && (cSecurityProfiles > 0))
		{
			wprintf(L"Listing security profiles...\n");
			ListSecurityProfiles(cSecurityProfiles, pSecProfEntry);
		}
		else if ((RUNNINGMODE_CLEAR == pToolkitOptions->ulRunningMode))
		{
			wprintf(L"Clearing security profiles...\n");
			EC_HR(ClearSecurityProfiles(lpSession));
		}


		MAPIUninitialize();
		CoUninitialize();
	}
	catch (int exception)
	{
		printf("ERROR: hRes = 0%x\n", exception);
	}

Error:
	goto Cleanup;
Cleanup:
	return;
}

