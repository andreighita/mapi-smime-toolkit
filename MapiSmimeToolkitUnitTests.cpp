#include "stdafx.h"
#include "MapiSmimeToolkit.h"
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
		TEST_CLASS(MapiSmimeToolKitUnitTests)
		{
			TEST_METHOD(ParseArgs_NoArgs) 
			{
				vector<TCHAR*> vPassedArgs = {
					_T(""),
				};
				unique_ptr<ToolkitOptions> pToolkitOptions;

				Assert::IsFalse(ParseArgs(vPassedArgs.size(), vPassedArgs.data(), pToolkitOptions.get()), _T("The call ParseArgs suceeded."));
			}

			TEST_METHOD(ParseArgs_DontSendCertificates)
			{
				ToolkitOptions options;
				ZeroMemory(&options, sizeof(ToolkitOptions));
				vector<TCHAR*> vPassedArgs = {
					_T(""),
					_T("-u"),
					_T("irvins@contoso.com"),
					_T("-ds"),
				};

				Assert::IsTrue(ParseArgs(vPassedArgs.size(), vPassedArgs.data(), &options), _T("The call ParseArgs failed!"));
				Assert::IsTrue(options.wsEmailAddress == L"irvins@contoso.com", _T("The email is not correct."));
				Assert::IsTrue(options.bDontSendCertificates, _T("Don't send certificates should be false!"));
			}

			TEST_METHOD(ParseArgs_SpecifyDefaultSigningHashAlgorithm)
			{
				ToolkitOptions options;
				ZeroMemory(&options, sizeof(ToolkitOptions));
				vector<TCHAR*> vPassedArgs = {
					_T(""),
					_T("-u"),
					_T("irvins@contoso.com"),
					_T("-x"),
					_T("2.16.840.1.101.3.4.2.2"),
				};

				Assert::IsTrue(ParseArgs(vPassedArgs.size(), vPassedArgs.data(), &options), _T("The call ParseArgs failed!"));
				Assert::IsTrue(options.szDefaultSignatureHashOID == "2.16.840.1.101.3.4.2.2", _T("The Default Signature Hash OID was not parsed!"));
			}
		};
	}
}