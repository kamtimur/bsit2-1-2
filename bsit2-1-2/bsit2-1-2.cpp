// bsit2-1-2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <windows.h>
#include <LM.h>
#include <Ntsecapi.h>
#include <sddl.h>
#include <ntsecapi.h>


typedef DWORD	(WINAPI *NetLocalGroupEnumT)		(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
typedef NTSTATUS(WINAPI *LsaLookupNames2T)			(LSA_HANDLE, ULONG, ULONG, PLSA_UNICODE_STRING, PLSA_REFERENCED_DOMAIN_LIST*, PLSA_TRANSLATED_SID2*);
typedef BOOL	(WINAPI *ConvertSidToStringSidT)	(PSID, LPTSTR*);
typedef NTSTATUS(WINAPI *LsaFreeMemoryT)			(PVOID);
typedef DWORD	(WINAPI *NetApiBufferFreeT)			(PVOID);
typedef NTSTATUS(WINAPI *NetLocalGroupGetMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
typedef DWORD	(WINAPI *NetUserAddT)				(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD	(WINAPI *NetUserDelT)				(LPCWSTR, LPCWSTR);
typedef DWORD	(WINAPI *NetLocalGroupAddT)			(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD	(WINAPI *NetLocalGroupDelT)			(LPCWSTR, LPCWSTR);
typedef DWORD	(WINAPI *NetLocalGroupAddMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
typedef DWORD	(WINAPI *NetLocalGroupDelMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
typedef NTSTATUS(WINAPI *LsaAddAccountRightsT)		(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
typedef NTSTATUS(WINAPI *LsaRemoveAccountRightsT)	(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
typedef DWORD	(WINAPI *NetUserSetInfoT)			(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD	(WINAPI *NetUserChangePasswordT)	(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef	DWORD	(WINAPI *NetLocalGroupSetInfoT)		(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);



bool enum_groups_users();																				//работает
bool init_lsa_string(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString);								//работает
LSA_HANDLE pol_handle();																				//работает
void enum_acc_right_token(LPCWSTR username, LPCWSTR password);											
bool add_user(LPCWSTR username, LPCWSTR password);														//работает	
bool delete_user(LPCWSTR username);																		//работает
bool set_privilege(LPCWSTR username, LPCWSTR password, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
bool add_group(LPCWSTR group_name);																		//работает
bool delete_group(LPCWSTR group_name);																	//работает
bool add_user_to_group(LPCWSTR username, LPCWSTR groupname);											//работает
bool delete_user_from_group(LPCWSTR username, LPCWSTR groupname);										//работает
bool add_acc_rights(LPCWSTR name, LPCWSTR privilege);													//работает
bool del_acc_rights(LPCWSTR name, LPCWSTR privilege);													//работает
bool change_username(LPCWSTR name, LPCWSTR new_name);													//работает
bool change_user_pass(LPCWSTR name, LPCWSTR old_pass, LPCWSTR new_pass);								//работает
bool change_group_name(LPCWSTR name, LPCWSTR new_name);													//работает
bool enum_account_rights(LPCWSTR name);																	//работает
BOOL en_priv(LPCWSTR username, LPCWSTR password, LPCWSTR Name, BOOL Enabled);



//#define PRIV
//#define ADD_STATE
//#define DELETE_STATE
//#define RENAME
//#define PRIVILEGE
//#define INHERIT
int main()
{
	setlocale(LC_ALL, "Russian");
	LPCWSTR user = L"bsit1_user";
	LPCWSTR user2 = L"bsit2_user";
	LPCWSTR pass = L"bsit1_pass";
	LPCWSTR group_name = L"bsit1_group";
	bool status;
#ifdef ADD_STATE
	add_group(group_name);
	printf("\n");
	add_user(user, pass);
	printf("\n");
	add_user_to_group(user, group_name);
	printf("\n");
	enum_account_rights(user);
	printf("\n");
	add_acc_rights(user, SE_DEBUG_NAME);
	printf("\n");
	enum_account_rights(user);
	printf("\n");
	del_acc_rights(user, SE_DEBUG_NAME);
	printf("\n");
	enum_account_rights(user);
	printf("\n");
	enum_groups_users();
#endif // ADD_STATE
	printf("\n");
	printf("\n");
	printf("\n");
#ifdef DELETE_STATE
	delete_user(user);
	printf("\n");
	delete_group(group_name);
	printf("\n");
#endif // DELETE_STATE
	printf("\n");
	printf("\n");
	printf("\n");
#ifdef RENAME
	LPCWSTR newuser = L"qwerty";
	LPCWSTR newpass = L"qwerty_pass";
	LPCWSTR newgroup_name = L"qwerty_group";
	add_group(group_name);
	printf("\n");
	add_user(user, pass);
	printf("\n");
	add_user_to_group(user, group_name);
	printf("\n");
	change_user_pass(user, pass, newpass);
	printf("\n");
	enum_acc_right_token(user, newpass);
	printf("\n");
	change_username(user, newuser);
	printf("\n");
	change_group_name(group_name, newgroup_name);
	printf("\n");
	enum_groups_users();
	printf("\n");
	printf("\n");
	printf("\n");
	delete_user(newuser);
	printf("\n");
	delete_group(newgroup_name);
	printf("\n");
#endif // RENAME
#ifdef PRIVILEGE
	//enum_groups_users();
	add_user(user, pass);
	add_acc_rights(user, (L"SeInteractiveLogonRight"));
	enum_account_rights(user);
	//set_privilege(user, pass, TEXT("SeInteractiveLogonRight"), true);
	//en_priv(user, pass, const_cast<LPWSTR>(L"SeInteractiveLogonRight"), true);
	//en_priv(user, pass, SE_DEBUG_NAME, true);
	en_priv(user, pass, (L"SeInteractiveLogonRight"), true);
	delete_user(user);
#endif
#ifdef INHERIT
	//add_user(user, pass);
	//enum_account_rights(user);
	////del_acc_rights(user, (L"SeInteractiveLogonRight"));
	//add_user_to_group(user, L"Администраторы");
	//enum_groups_users();
	//enum_account_rights(user);
	//delete_user(user);
	add_user(user2, pass);
	add_group(group_name);
	//SeChangeNotifyPrivilege
	//	SeIncreaseWorkingSetPrivilege
	//	SeShutdownPrivilege
	//	SeUndockPrivilege
	//	SeTimeZonePrivilege
	//	SeInteractiveLogonRight
	//	SeNetworkLogonRight
	add_acc_rights(user2, SE_INTERACTIVE_LOGON_NAME);
	add_acc_rights(user2, SE_NETWORK_LOGON_NAME);
	add_acc_rights(user2, SE_BATCH_LOGON_NAME);
	add_acc_rights(user2, SE_SERVICE_LOGON_NAME);
	add_acc_rights(user2, SE_REMOTE_INTERACTIVE_LOGON_NAME);
	add_acc_rights(user2, (L"SeIncreaseWorkingSetPrivilege"));
	add_acc_rights(user2, (L"SeShutdownPrivilege"));
	add_acc_rights(user2, (L"SeUndockPrivilege"));
	add_acc_rights(user2, (L"SeTimeZonePrivilege"));

	add_acc_rights(group_name, SE_INTERACTIVE_LOGON_NAME);
	add_acc_rights(group_name, SE_NETWORK_LOGON_NAME);
	add_acc_rights(group_name, SE_BATCH_LOGON_NAME);
	add_acc_rights(group_name, SE_SERVICE_LOGON_NAME);
	add_acc_rights(group_name, SE_REMOTE_INTERACTIVE_LOGON_NAME);
	add_acc_rights(group_name, (L"SeIncreaseWorkingSetPrivilege"));
	add_acc_rights(group_name, (L"SeShutdownPrivilege"));
	add_acc_rights(group_name, (L"SeUndockPrivilege"));
	add_acc_rights(group_name, (L"SeTimeZonePrivilege"));

	en_priv(user2, pass, (L"SeIncreaseWorkingSetPrivilege"), true);
	en_priv(user2, pass, (L"SeShutdownPrivilege"), true);
	en_priv(user2, pass, (L"SeUndockPrivilege"), true);
	en_priv(user2, pass, (L"SeTimeZonePrivilege"), true);

	enum_account_rights(user2);
	add_user_to_group(user2, group_name);
#endif
	//delete_user(L"User2");
	//delete_user(L"User1");
	//delete_user(L"Doctor2");
	//delete_user(L"Doctor1");
	delete_group(L"Users_MBKS");
	delete_group(L"Doctors_MBKS");
	enum_groups_users();
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
		DWORD usersEntriesread = 0;
		DWORD usersTotalentries = 0;
		DWORD_PTR usersResumehandle = NULL;
		LOCALGROUP_MEMBERS_INFO_2 * buf = NULL;
		status = NetLocalGroupGetMembers(NULL, group_names[i], 2, (BYTE**)&buf, MAX_PREFERRED_LENGTH, &usersEntriesread, &usersTotalentries, &usersResumehandle);
		if (status != 0)
		{
			printf("NetLocalGroupGetMembers error %d\n", status);
			return false;
		}
		wprintf(L"%s %s\n", group_names[i], groupStringSid[i]);
#ifdef PRIV
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
#endif // PRIV
		for (int j = 0; j < usersEntriesread; j++)
		{
			PSID         lgrmi2_sid = buf[j].lgrmi2_sid;
			LPWSTR       lgrmi2_domainandname = buf[j].lgrmi2_domainandname;
			LPWSTR userStringSid[100];
			rc = ConvertSidToStringSid(lgrmi2_sid, &userStringSid[j]);
			wprintf(L"\t%s %s\n", lgrmi2_domainandname, userStringSid[j]);
#ifdef PRIV
			PLSA_UNICODE_STRING rights;
			ULONG count;
			NTSTATUS status = LsaEnumerateAccountRights(pol_handle(), lgrmi2_sid, &rights, &count);
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
#endif
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

bool add_user(LPCWSTR username, LPCWSTR password)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetUserAddT NetUserAdd = (NetUserAddT)GetProcAddress(Netapi32, "NetUserAdd");
	if (NetUserAdd == NULL)
	{
		printf("No such function NetUserAdd");
		return false;
	}
	USER_INFO_1 ui;
	ui.usri1_name = const_cast<LPWSTR>(username);
	ui.usri1_password = const_cast<LPWSTR>(password);
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;
	ui.usri1_script_path = NULL;
	DWORD dwError = NetUserAdd(0, 1, (LPBYTE)&ui, &dwError);
	if (dwError!=0)
	{
		printf("NetLocalGroupSetInfo error\n");
		return false;
	}
	printf("add_user success\n");
	return true;
}

bool delete_user(LPCWSTR username)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetUserDelT NetUserDel = (NetUserDelT)GetProcAddress(Netapi32, "NetUserDel");
	if (NetUserDel == NULL)
	{
		printf("No such function NetUserDel");
		return false;
	}

	if (NetUserDel(0, username))
	{
		printf("NetLocalGroupSetInfo error\n");
		return false;
	}
	printf("delete_user success\n");
	return true;
}

bool set_privilege(LPCWSTR username, LPCWSTR password, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	HANDLE token;
	if (!LogonUser(username, 0, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
	{
		printf("Error logon process\n");
		return false;
	}
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		token,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL)) {
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool add_group(LPCWSTR groupname)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}

	NetLocalGroupAddT NetLocalGroupAdd = (NetLocalGroupAddT)GetProcAddress(Netapi32, "NetLocalGroupAdd");
	if (NetLocalGroupAdd == NULL)
	{
		printf("No such function NetLocalGroupAdd");
		return false;
	}

	_LOCALGROUP_INFO_0 lgi;
	lgi.lgrpi0_name = const_cast<LPWSTR>(groupname);
	DWORD ret = NetLocalGroupAdd(0, 0, (LPBYTE)&lgi, 0);
	if (ret != 0)
	{
		printf("NetLocalGroupAdd error\n");
		return false;
	}
	printf("add_group success\n");
	return true;
}

bool delete_group(LPCWSTR groupname)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetLocalGroupDelT NetLocalGroupDel = (NetLocalGroupDelT)GetProcAddress(Netapi32, "NetLocalGroupDel");
	if (NetLocalGroupDel == NULL)
	{
		printf("No such function NetLocalGroupDel");
		return false;
	}

	if (NetLocalGroupDel(0, groupname))
	{
		printf("NetLocalGroupDel error\n");
		return false;
	}
	printf("NetLocalGroupDel succsess\n");
	return true;
}

bool add_user_to_group(LPCWSTR username, LPCWSTR groupname)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetLocalGroupAddMembersT NetLocalGroupAddMembers = (NetLocalGroupAddMembersT)GetProcAddress(Netapi32, "NetLocalGroupAddMembers");
	if (NetLocalGroupAddMembers == NULL)
	{
		printf("No such function NetLocalGroupAddMembers");
		return false;
	}
	LOCALGROUP_MEMBERS_INFO_3 lgmi3;
	lgmi3.lgrmi3_domainandname = (LPWSTR)username;
	NTSTATUS status = NetLocalGroupAddMembers(0, groupname, 3, (LPBYTE)&lgmi3, 1);
	if (status !=0)
	{
		printf("NetLocalGroupAddMembers error\n");
		return false;
	}
	printf("add_user_to_group success\n");
	return true;
}

bool delete_user_from_group(LPCWSTR username, LPCWSTR groupname)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetLocalGroupDelMembersT NetLocalGroupDelMembers = (NetLocalGroupDelMembersT)GetProcAddress(Netapi32, "NetLocalGroupDelMembers");
	if (NetLocalGroupDelMembers == NULL)
	{
		printf("No such function NetLocalGroupDelMembers");
		return false;
	}

	LOCALGROUP_MEMBERS_INFO_3 lgmi3;
	lgmi3.lgrmi3_domainandname = const_cast<LPWSTR>(username);
	if (NetLocalGroupDelMembers(0, groupname, 3, (LPBYTE)&lgmi3, 1))
	{
		printf("NetLocalGroupDelMembers error\n");
		return false;
	}
	printf("delete_user_from_group success\n");
	return true;
}

bool add_acc_rights(LPCWSTR name, LPCWSTR privilege)
{
	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
	{
		printf("No such library Advapi32.dll");
		return false;
	}
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetLocalGroupEnumT NetLocalGroupEnum = (NetLocalGroupEnumT)GetProcAddress(Netapi32, "NetLocalGroupEnum");
	if (NetLocalGroupEnum == NULL)
	{
		printf("No such function NetLocalGroupEnum");
		return false;
	}
	LsaAddAccountRightsT LsaAddAccountRights = (LsaAddAccountRightsT)GetProcAddress(Advapi32, "LsaAddAccountRights");
	if (LsaAddAccountRights == NULL)
	{
		printf("No such function LsaAddAccountRights");
		return false;
	}
	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
	{
		printf("No such function LsaLookupNames2");
		return false;
	}
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	LSA_UNICODE_STRING pLsaStringName;
	LSA_UNICODE_STRING pLsaStringPrivilege;
	bool rc;
	rc = init_lsa_string(&pLsaStringName, name);
	if (!rc)
	{
		printf("name into lsa error %d");
		return false;
	}
	rc = init_lsa_string(&pLsaStringPrivilege, privilege);
	if (!rc)
	{
		printf("name into lsa error %d");
		return false;
	}
	NTSTATUS status = LsaLookupNames2(pol_handle(), 0x80000000, 1, &pLsaStringName, &ReferencedDomains, &sid);
	if (status != 0)
	{
		printf("LsaLookupNames2 error");
		return false;
	}
	status = LsaAddAccountRights(pol_handle(), sid, &pLsaStringPrivilege, 1);
	if (status != 0)
	{
		printf("LsaAddAccountRights error\n");
		return false;
	}
	printf("add_acc_rights success\n");
	return true;
}

bool del_acc_rights(LPCWSTR name, LPCWSTR privilege)
{
	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
	{
		printf("No such library Advapi32.dll");
		return false;
	}
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
	{
		printf("No such function LsaLookupNames2");
		return false;
	}
	LsaRemoveAccountRightsT LsaRemoveAccountRights = (LsaRemoveAccountRightsT)GetProcAddress(Advapi32, "LsaRemoveAccountRights");
	if (LsaRemoveAccountRights == NULL)
	{
		printf("No such function LsaRemoveAccountRights");
		return false;
	}

	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	bool rc;
	LSA_UNICODE_STRING pLsaStringName;
	LSA_UNICODE_STRING pLsaStringPrivilege;
	rc = init_lsa_string(&pLsaStringName, name);
	if (!rc)
	{
		printf("name into lsa error %d");
		return false;
	}
	rc = init_lsa_string(&pLsaStringPrivilege, privilege);
	if (!rc)
	{
		printf("name into lsa error %d");
		return false;
	}
	NTSTATUS status = LsaLookupNames2(pol_handle(), 0x80000000, 1, &pLsaStringName, &ReferencedDomains, &sid);
	if (status != 0)
	{
		printf("LsaLookupNames2 error");
		return false;
	}
	if (LsaRemoveAccountRights(pol_handle(), sid, 0, &pLsaStringPrivilege, 1))
	{
		printf("LsaRemoveAccountRights error\n");
		return false;
	}
	printf("del_acc_rights success\n");
	return true;

}

bool change_username(LPCWSTR name, LPCWSTR new_name)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetUserSetInfoT NetUserSetInfo = (NetUserSetInfoT)GetProcAddress(Netapi32, "NetUserSetInfo");
	if (NetUserSetInfo == NULL)
	{
		printf("No such function NetUserSetInfo");
		return false;
	}
	USER_INFO_0 pBuf;
	pBuf.usri0_name = const_cast<LPWSTR>(new_name);
	NET_API_STATUS dwerr = NetUserSetInfo(0, name, 0, (LPBYTE)&pBuf, 0);
	if (dwerr == 0)
	{
		wprintf(L"user '%s' was changed to '%s' \n\n", name, new_name);
		return true;
	}
	else
	{
		wprintf(L"error while changing user's general settings");
		return false;
	}
}

bool change_user_pass(LPCWSTR name, LPCWSTR old_pass, LPCWSTR new_pass)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetUserChangePasswordT NetUserChangePassword = (NetUserChangePasswordT)GetProcAddress(Netapi32, "NetUserChangePassword");
	if (NetUserChangePassword == NULL)
	{
		printf("No such function NetUserChangePassword");
		return false;
	}
	DWORD dwError = NetUserChangePassword(NULL, name, old_pass, new_pass);
	if (dwError!=0)
	{
		printf("NetUserChangePassword error\n");
		return false;
	}
	printf("change_user_pass success\n");
	return true;
}

bool change_group_name(LPCWSTR name, LPCWSTR new_name)
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
	{
		printf("No such library Netapi32.dll");
		return false;
	}
	NetLocalGroupSetInfoT NetLocalGroupSetInfo = (NetLocalGroupSetInfoT)GetProcAddress(Netapi32, "NetLocalGroupSetInfo");
	if (NetLocalGroupSetInfo == NULL)
	{
		printf("No such function NetLocalGroupSetInfo");
		return false;
	}
	LOCALGROUP_INFO_0 lcgrstructure;
	lcgrstructure.lgrpi0_name = const_cast<LPWSTR>(new_name);
	if (NetLocalGroupSetInfo(0, name, 0, (LPBYTE)&lcgrstructure, 0))
	{
		printf("NetLocalGroupSetInfo error\n");
		return false;
	}
	printf("change_group_name success\n");
	return true;
}

bool enum_account_rights(LPCWSTR name)
{
	NTSTATUS status;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	LSA_UNICODE_STRING pLsaString;
	bool rc = init_lsa_string(&pLsaString, name);
	status = LsaLookupNames2(pol_handle(), 0x80000000, 1, &pLsaString, &ReferencedDomains, &sid);
	if (status == 0) {
		PLSA_UNICODE_STRING rights = NULL;
		ULONG count = 0;
		status = LsaEnumerateAccountRights(pol_handle(), sid, &rights, &count); //для пользователей, назначенные непосредственно ему, функция AddAccountRights
		if (status != 0) {
			if (LsaNtStatusToWinError(status) == 87) { //для групп
				status = LsaEnumerateAccountRights(pol_handle(), sid[0].Sid, &rights, &count);
				if (status != 0)
					wprintf(L"Код ошибки получения привилегий: %lu\n", LsaNtStatusToWinError(status));
			}
			else
				wprintf(L"Код ошибки получения привилегий: %lu\n", LsaNtStatusToWinError(status));
		}
		for (ULONG k = 0; k < count; k++)
		{
			wprintf(L"%s\n", rights[k].Buffer);
		}
	}
	else {
		wprintf(L"Код ошибки получения SID: %lu\n", LsaNtStatusToWinError(status));
	}
	return true;
}

BOOL en_priv(LPCWSTR username, LPCWSTR password, LPCWSTR Name, BOOL Enabled) 
{
	HANDLE token;
	if (!LogonUser(username, 0, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
	{
		printf("Error logon process\n");
		return false;
	}
	LUID luid;


	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		Name,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return false;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = Enabled ? SE_PRIVILEGE_ENABLED : 0; // not use SE_PRIVILEGE_REMOVED, just disable

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		wprintf(L"AdjustTokenPrivileges failed - 0x%08x\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		wprintf(L"The process token does not have %s (%I64d).\n", Name, luid);
		return FALSE;
	}

	wprintf(L"%s (%I64d) is temporarily %s.\n", Name, luid,
		Enabled ? L"enabled" : L"disabled");

	return TRUE;
}