#include "stdafx.h"
#include "SecurityProfile.h"
#include <CppUnitTest.h>
#include <memory>
#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;

// Note: You must have selected the Debug (Test) x86 build configuration for these settings to work. If you have x64 installed they won't work either
// without changes made to the configuration. Also, the build output must be an .dll to allow for unit testing.

namespace MapiSmimeToolKit
{
	namespace Tests
	{
		TEST_CLASS(SecurityProfileUnitTests) {

			bool FindDataForTag(WORD tagSought, LPSBinary lpbData, WORD * cbData, LPBYTE * data)
			{
				WORD pos = 0;
				LPBYTE lpb = lpbData->lpb;

				*cbData = 0;
				*data = nullptr;
				while (pos < lpbData->cb)
				{ 
					WORD tag = *lpb;
					WORD dataLength = *(lpb + sizeof(WORD));
					WORD adjustedDatalength = dataLength - (sizeof(WORD) * 2);
					LPBYTE lpData = lpb + (sizeof(WORD) * 2);
 					if (tagSought == tag)
					{
						*cbData = adjustedDatalength;
						*data = lpData;
						return true;
					}
					pos += dataLength;
					lpb += dataLength;
				}

				return false;
			}

			TEST_METHOD(NewSecurityProfileTest_CreateDefaultProfile) {
				SBinary lpSecProfile = { 0, 0 };
				vector<byte> CertHash = { 0x3E,0xA4, 0x9B,0x28,0x17,0x0B,0x9D,0x5F,0x29,0x1A,0xC1,0xEE,0x20,0x35,0x0A,0xEA,0xD5,0xDE,0xBE,0x93 };
				wstring profileName(L"TestProfile1");
				string szProfileName;
				szProfileName.assign(profileName.begin(), profileName.end());
				// Set up the SMIME Caps with the default order
				std::vector<CRYPT_SMIME_CAPABILITY> vSMIMECapabilites{
					{ szOID_NIST_sha256, 0, nullptr },
					{ szOID_NIST_sha384, 0, nullptr },
					{ szOID_NIST_sha512, 0, nullptr },
					{ szOID_NIST_AES256_CBC, 0, nullptr },
					{ szOID_NIST_AES192_CBC, 0, nullptr },
					{ szOID_NIST_AES128_CBC, 0, nullptr },
				};

				CRYPT_SMIME_CAPABILITIES Capabilities;
				ZeroMemory(&Capabilities, sizeof(Capabilities));
				Capabilities.cCapability = vSMIMECapabilites.size();
				Capabilities.rgCapability = vSMIMECapabilites.data();

				DWORD cbEncoded = 0;

				CryptEncodeObject(
					X509_ASN_ENCODING,        // the encoding/decoding type
					PKCS_SMIME_CAPABILITIES,
					&Capabilities,
					NULL,
					&cbEncoded);

				unique_ptr<byte[]> pEncoded = unique_ptr<byte[]>(new byte[cbEncoded]);
				ZeroMemory(pEncoded.get(), cbEncoded);

				CryptEncodeObject(
					X509_ASN_ENCODING,        // the encoding/decoding type
					PKCS_SMIME_CAPABILITIES,
					&Capabilities,
					pEncoded.get(),
					&cbEncoded);

				HRESULT hRes = NewSecurityProfile(
									CertHash.size(), // Signing Hash size
									CertHash.data(), // Signing Hash data
									CertHash.size(), // Enc Hash size
									CertHash.data(), // Enc Hash Data
									profileName, // Profile Name
									true, // Is default profile
									std::string(), // OID Default Signature Hash
									false, // Don't send certificates
									&lpSecProfile); // Security Profile

				Assert::IsTrue(hRes == S_OK, L"Could not create NewSecurityProfile.");
				Assert::IsFalse(0 == lpSecProfile.cb, L"The count of bytes of the returned SBinrary must be greater than zero!");
				Assert::IsNotNull(lpSecProfile.lpb);
				LPBYTE lpb = lpSecProfile.lpb;
				ULONG pos = 0;
				while (pos < lpSecProfile.cb)
				{
					WORD tag = *lpb;
					WORD dataLength = *(lpb + sizeof(WORD));
					WORD adjustedDatalength = dataLength - (sizeof(WORD) * 2);
					LPBYTE lpData = lpb + (sizeof(WORD) * 2);
					int i = 0;
					switch (tag)
					{
					case PROP_ID(PR_CERT_PROP_VERSION):
						Assert::IsTrue(*((WORD*)lpData) == 1, _T("The version must be 1."));
						break;
					case PROP_ID(PR_CERT_MESSAGE_ENCODING):
						Assert::IsTrue(*((WORD*)lpData) == 1, _T("The encoding must be 1."));
						break;
					case PROP_ID(PR_CERT_DISPLAY_NAME_A):
						Assert::IsTrue(((szProfileName.size() + 1) * sizeof(CHAR)) == adjustedDatalength, _T("PR_CERT_DISPLAY_NAME_A's size is incorrect."));
						Assert::IsTrue(szProfileName.compare((LPSTR)lpData) == 0, _T("PR_CERT_DISPLAY_NAME_A is incorrect."));
						break;
					case PROP_ID(PR_CERT_DISPLAY_NAME_W):
						Assert::IsTrue(((profileName.size() + 1) * sizeof(WCHAR)) == adjustedDatalength, _T("PR_CERT_DISPLAY_NAME_W's size is incorrect."));
						Assert::IsTrue(profileName.compare((LPWSTR)lpData) == 0, _T("PR_CERT_DISPLAY_NAME_W is incorrect."));
						break;
					case PROP_ID(PR_CERT_ASYMETRIC_CAPS):
						Assert::IsTrue(cbEncoded == adjustedDatalength, _T("PR_CERT_ASYMETRIC_CAPS's size is incorrect."));
						i = 0;
						while (i < cbEncoded)
						{
							Assert::IsTrue(pEncoded.get()[i] == lpData[i], _T("Invalid byte value found in bytes of PR_CERT_ASYMETRIC_CAPS"));
							i++;
						}
						break;
					case PROP_ID(PR_CERT_KEYEX_SHA1_HASH):
					case PROP_ID(PR_CERT_SIGN_SHA1_HASH):
						Assert::IsFalse(adjustedDatalength == 0, _T("No hash provided."));
						Assert::IsTrue(CertHash.size() == adjustedDatalength, _T("The size of the hash is incorrect."));
						for each (auto itr in CertHash)
						{
							Assert::IsTrue(itr == lpData[i], _T("Invalid byte value found in bytes of hash."));
							i++;
						}
						break;
					case PROP_ID(PR_CERT_DEFAULTS):
						Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_FOR_FORMAT) == MSG_DEFAULTS_FOR_FORMAT, _T("The default format is incorrect."));
						Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_GLOBAL) == MSG_DEFAULTS_GLOBAL, _T("The default global value is incorrect."));
						Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_SEND_CERT) == MSG_DEFAULTS_SEND_CERT, _T("The send cert value is incorrect."));
						break;
					default:
						break;
					}
					pos += dataLength;
					lpb += dataLength;
				}

				free(lpSecProfile.lpb);
			}

			TEST_METHOD(NewSecurityProfileTest_SetDefaultSignatureHash)
			{
				SBinary lpSecProfile = { 0, 0 };
				vector<byte> CertHash = { 0x3E,0xA4, 0x9B,0x28,0x17,0x0B,0x9D,0x5F,0x29,0x1A,0xC1,0xEE,0x20,0x35,0x0A,0xEA,0xD5,0xDE,0xBE,0x93 };
				wstring profileName(L"TestProfile1");
				string szProfileName;
				szProfileName.assign(profileName.begin(), profileName.end());
				string defaultHashSignatureAlg("2.16.840.1.101.3.4.2.2");
				int i = 0;

				// Set up the SMIME Caps with the sha384 as the preferred order
				std::vector<CRYPT_SMIME_CAPABILITY> vSMIMECapabilites{
					{ szOID_NIST_sha384, 0, nullptr },
					{ szOID_NIST_sha256, 0, nullptr },
					{ szOID_NIST_sha512, 0, nullptr },
					{ szOID_NIST_AES256_CBC, 0, nullptr },
					{ szOID_NIST_AES192_CBC, 0, nullptr },
					{ szOID_NIST_AES128_CBC, 0, nullptr },
				};

				CRYPT_SMIME_CAPABILITIES Capabilities;
				ZeroMemory(&Capabilities, sizeof(Capabilities));
				Capabilities.cCapability = vSMIMECapabilites.size();
				Capabilities.rgCapability = vSMIMECapabilites.data();

				DWORD cbEncoded = 0;

				CryptEncodeObject(
					X509_ASN_ENCODING,        // the encoding/decoding type
					PKCS_SMIME_CAPABILITIES,
					&Capabilities,
					NULL,
					&cbEncoded);

				unique_ptr<byte[]> pEncoded = unique_ptr<byte[]>(new byte[cbEncoded]);
				ZeroMemory(pEncoded.get(), cbEncoded);

				CryptEncodeObject(
					X509_ASN_ENCODING,        // the encoding/decoding type
					PKCS_SMIME_CAPABILITIES,
					&Capabilities,
					pEncoded.get(),
					&cbEncoded);

				HRESULT hRes = NewSecurityProfile(
									CertHash.size(), // Signing Hash size
									CertHash.data(), // Signing Hash data
									CertHash.size(), // Enc Hash size
									CertHash.data(), // Enc Hash Data
									profileName, // Profile Name
									true, // Is default profile
									defaultHashSignatureAlg, // OID Default Signature Hash
									true, // Don't send certificates
									&lpSecProfile); // Security Profile

				Assert::IsTrue(hRes == S_OK, L"Could not create NewSecurityProfile (Do not send).");
				Assert::IsFalse(0 == lpSecProfile.cb, L"The count of bytes of the returned SBinrary must be greater than zero! (Do not send)");
				Assert::IsNotNull(lpSecProfile.lpb);

				LPBYTE lpData = nullptr;
				WORD cb = 0;
				Assert::IsTrue(FindDataForTag(PROP_ID(PR_CERT_ASYMETRIC_CAPS), &lpSecProfile, &cb, &lpData), _T("Could not find tag PR_CERT_ASYMETRIC_CAPS"));
				Assert::IsNotNull(lpData, _T("Couldn't get PR_CERT_ASYMETRIC_CAPS caps!"));
				Assert::IsTrue(cb == cbEncoded, _T("The encoded count is not correct."));
				i = 0;
				while (i < cbEncoded)
				{
					Assert::IsTrue(pEncoded.get()[i] == lpData[i], _T("Invalid byte value found in bytes of PR_CERT_ASYMETRIC_CAPS"));
					i++;
				}

				free(lpSecProfile.lpb);
			}

			TEST_METHOD(NewSecurityProfile_DontSendCertificates)
			{
				SBinary lpSecProfile = { 0, 0 };
				vector<byte> CertHash = { 0x3E,0xA4, 0x9B,0x28,0x17,0x0B,0x9D,0x5F,0x29,0x1A,0xC1,0xEE,0x20,0x35,0x0A,0xEA,0xD5,0xDE,0xBE,0x93 };
				wstring profileName(L"TestProfile1");
				string szProfileName;
				szProfileName.assign(profileName.begin(), profileName.end());
				HRESULT hRes = NewSecurityProfile(
					CertHash.size(), // Signing Hash size
					CertHash.data(), // Signing Hash data
					CertHash.size(), // Enc Hash size
					CertHash.data(), // Enc Hash Data
					profileName, // Profile Name
					true, // Is default profile
					std::string(), // OID Default Signature Hash
					true, // Don't send certificates
					&lpSecProfile); // Security Profile

				Assert::IsTrue(hRes == S_OK, L"Could not create NewSecurityProfile (Do not send).");
				Assert::IsFalse(0 == lpSecProfile.cb, L"The count of bytes of the returned SBinrary must be greater than zero! (Do not send)");
				Assert::IsNotNull(lpSecProfile.lpb);

				LPBYTE lpData = nullptr;
				WORD cb = 0;
				Assert::IsTrue(FindDataForTag(PROP_ID(PR_CERT_DEFAULTS), &lpSecProfile, &cb, &lpData), _T("Could not find tag PR_CERT_DEFAULTS"));

				Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_FOR_FORMAT) == MSG_DEFAULTS_FOR_FORMAT, _T("The default format is incorrect."));
				Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_GLOBAL) == MSG_DEFAULTS_GLOBAL, _T("The default global value is incorrect."));
				Assert::IsTrue((*((WORD*)lpData) & MSG_DEFAULTS_SEND_CERT) == 0, _T("The send cert value is incorrect."));
				free(lpSecProfile.lpb);
			}
		};
	}
}