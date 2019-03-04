// bsit2-1-2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <windows.h>
#include <LM.h>
#include <Ntsecapi.h>
#include <sddl.h>


typedef DWORD(WINAPI *NetLocalGroupEnumT)		(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
typedef NTSTATUS(WINAPI *LsaLookupNames2T)		(LSA_HANDLE, ULONG, ULONG, PLSA_UNICODE_STRING, PLSA_REFERENCED_DOMAIN_LIST*, PLSA_TRANSLATED_SID2*);
typedef BOOL(WINAPI *ConvertSidToStringSidT)	(PSID, LPTSTR*);
typedef NTSTATUS(WINAPI *LsaFreeMemoryT)		(PVOID);
typedef DWORD(WINAPI *NetApiBufferFreeT)		(PVOID);
typedef NTSTATUS(WINAPI *NetLocalGroupGetMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);

bool enum_groups_users();
bool init_lsa_string(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);
LSA_HANDLE pol_handle();
void enum_acc_right_token(LPCWSTR username, LPCWSTR password);


int main()
{
	setlocale(LC_ALL, "Russian");
	//enum_groups_users();

	//LPCWSTR user = L"tkn";
	//LPCWSTR pass = L"Xq1mn123";
	//enum_acc_right_token(user, pass);



	return 0;
}

bool enum_groups_users()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}

	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
	{
		printf("No such library Advapi32.dll");
		return false;
	}
	NetLocalGroupEnumT NetLocalGroupEnum = (NetLocalGroupEnumT)GetProcAddress(Netapi32, "NetLocalGroupEnum");
	if (NetLocalGroupEnum == NULL)
	{
		printf("No such function NetLocalGroupEnum");
		return false;
	}

	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
	{
		printf("No such function LsaLookupNames2");
		return false;
	}

	ConvertSidToStringSidT ConvertSidToStringSid = (ConvertSidToStringSidT)GetProcAddress(Advapi32, "ConvertSidToStringSidW");
	if (ConvertSidToStringSid == NULL)
	{
		printf("No such function ConvertSidToStringSidW");
		return false;
	}

	LsaFreeMemoryT LsaFreeMemory = (LsaFreeMemoryT)GetProcAddress(Advapi32, "LsaFreeMemory");
	if (LsaFreeMemory == NULL)
	{
		printf("No such function LsaFreeMemory");
		return false;
	}

	NetApiBufferFreeT NetApiBufferFree = (NetApiBufferFreeT)GetProcAddress(Netapi32, "NetApiBufferFree");
	if (NetApiBufferFree == NULL)
	{
		printf("No such function NetApiBufferFree");
		return false;
	}

	NetLocalGroupGetMembersT NetLocalGroupGetMembers = (NetLocalGroupGetMembersT)GetProcAddress(Netapi32, "NetLocalGroupGetMembers");
	if (NetLocalGroupGetMembers == NULL)
	{
		printf("No such function NetLocalGroupGetMembers");
		return false;
	}
	PLOCALGROUP_INFO_0 pGroupsBuf = NULL;
	DWORD groupsTotalentries = 0;
	DWORD groupsEntriesread = 0;
	DWORD_PTR groupsResumehandle = NULL;

	DWORD ret = NetLocalGroupEnum(NULL, 0, (LPBYTE *)&pGroupsBuf, MAX_PREFERRED_LENGTH, &groupsEntriesread, &groupsTotalentries, &groupsResumehandle);
	if (ret != NERR_Success)
	{
		printf("NetLocalGroupEnum error %d", ret);
		return false;
	}

	LPWSTR group_names[100];
	LSA_UNICODE_STRING pLsaString[100];
	bool rc;
	for (int i = 0; i < groupsEntriesread; i++)
	{
		group_names[i] = (pGroupsBuf[i].lgrpi0_name);
		rc = init_lsa_string(&pLsaString[i], group_names[i]);
		if (!rc)
		{
			printf("group_names into lsa error %d", ret);
			return false;
		}
	}

	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;

	NTSTATUS status = LsaLookupNames2(pol_handle(), 0x80000000, groupsEntriesread, pLsaString, &ReferencedDomains, &sid);

	if (status != 0)
	{
		printf("LsaLookupNames2 error");
		return false;
	}

	LPWSTR groupStringSid[100];
	for (int i = 0; i < groupsEntriesread; i++)
	{


		rc = ConvertSidToStringSid(sid[i].Sid, &groupStringSid[i]);
		if (!rc)
		{
			printf("sid into string error");
			return false;
		}
	}

	for (int i = 0; i < groupsEntriesread; i++)
	{
		//enum_users(group_names[i]);
		DWORD usersEntriesread = 0;
		DWORD usersTotalentries = 0;
		DWORD_PTR usersResumehandle = NULL;
		LOCALGROUP_MEMBERS_INFO_2 * buf = NULL;
		status = NetLocalGroupGetMembers(NULL, group_names[i], 2, (BYTE**)&buf, MAX_PREFERRED_LENGTH, &usersEntriesread, &usersTotalentries, &usersResumehandle);
		if (status != 0)
		{
			//system("cls");
			printf("NetLocalGroupGetMembers error %d\n", status);
			//system("cls");
			return false;
		}
		wprintf(L"%s %s\n", group_names[i], groupStringSid[i]);

		PLSA_UNICODE_STRING rights;
		ULONG count;
		NTSTATUS status = LsaEnumerateAccountRights(pol_handle(), sid[i].Sid, &rights, &count);
		if (status != 0)
		{
			//printf("LsaEnumerateAccountRights error");
			//return false;
		}
		for (ULONG k = 0; k < count; k++)
		{
			wprintf(L"____%s\n", (rights + k)->Buffer);
			//rights+ count;
		}
		LsaFreeMemory(rights);


		for (int j = 0; j < usersEntriesread; j++)
		{
			PSID         lgrmi2_sid = buf[j].lgrmi2_sid;
			LPWSTR       lgrmi2_domainandname = buf[j].lgrmi2_domainandname;
			LPWSTR userStringSid[100];
			rc = ConvertSidToStringSid(lgrmi2_sid, &userStringSid[j]);
			wprintf(L"\t%s %s\n", lgrmi2_domainandname, userStringSid[j]);
		}



		if (buf)
		{
			ret = NetApiBufferFree(buf);
			if (ret != NERR_Success)
			{
				printf("NetApiBufferFree error %d", ret);

				return false;
			}
		}
	}
	status = LsaFreeMemory(sid);
	if (status != 0)
	{
		printf("LsaFreeMemory error");
		return false;
	}
	if (pGroupsBuf)
	{
		ret = NetApiBufferFree(pGroupsBuf);
		if (ret != NERR_Success)
		{
			printf("NetApiBufferFree error %d", ret);
			return false;
		}
	}
	if (!FreeLibrary(Netapi32))
	{
		printf("FreeLibrary Netapi32 error");
		return false;
	}
	if (!FreeLibrary(Advapi32))
	{
		printf("FreeLibrary Advapi32 error");
		return false;
	}
	return true;
}

bool init_lsa_string(	PLSA_UNICODE_STRING pLsaString,	LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

LSA_HANDLE pol_handle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	// Object attributes are reserved, so initialize to zeros.
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// Get a handle to the Policy object.
	ntsResult = LsaOpenPolicy(
		NULL,    //Name of the target system.
		&ObjectAttributes, //Object attributes.
		POLICY_ALL_ACCESS, //POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION, //Desired access permissions.
		&lsahPolicyHandle  //Receives the policy handle.
	);

	if (ntsResult != 0)
	{
		// An error occurred. Display it as a win32 error code.
		wprintf(L"OpenPolicy returned %lu\n",
			LsaNtStatusToWinError(ntsResult));
		return NULL;
	}
	return lsahPolicyHandle;
}

void enum_acc_right_token(LPCWSTR username, LPCWSTR password)
{
	//WCHAR username[127];
	//WCHAR password[127];
	//printf("User name: ");	_getws_s(username);
	//printf("User password: "); _getws_s(password);
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	LSA_UNICODE_STRING pLsaString;
	bool rc;
	rc = init_lsa_string(&pLsaString, username);
	if (!rc)
	{
		printf("group_names into lsa error %d");
		return;
	}
	LsaLookupNames2(pol_handle(), 0x80000000, 1, &pLsaString, &ReferencedDomains, &sid);
	HANDLE token;
	TCHAR  privilegeName[256];
	DWORD PrivilegeName;
	if (!LogonUser(username, 0, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
	{
		printf("Error logon process\n");
		return;
	}
	DWORD dwLen = NULL;
	PTOKEN_PRIVILEGES priv = NULL;
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &dwLen);
	priv = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if (!GetTokenInformation(token, TokenPrivileges, priv, dwLen, &dwLen))
	{
		printf("Error gettoken process\n");
		return;
	}
	for (DWORD i = 0; i < priv->PrivilegeCount; i++)
	{
		PrivilegeName = 256;
		LookupPrivilegeName(NULL, &priv->Privileges[i].Luid, (LPWSTR)privilegeName, &PrivilegeName);
		if ((priv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED || (priv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
			wprintf(L"%s\n", privilegeName);
	}
	HeapFree(GetProcessHeap(), 0, priv);
	CloseHandle(token);
}