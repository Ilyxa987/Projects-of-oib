#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <AclAPI.h>
#include <lm.h>

PSID PrintUsers() {
	char* name = "C:\\Users\\Ilya\\Projects of oib\\Laba3\\g.txt";
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	PSID sids[20];
	LPVOID getace;
	PACCESS_ALLOWED_ACE ace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	SID_NAME_USE puse;
	int user = 0;
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {
		int countUsers = Dacl->AceCount;
		printf("������� ������������:\n");
		for (int i = 0; i < countUsers; i++) {
			GetAce(Dacl, i, &getace);
			ace = (PACCESS_ALLOWED_ACE)getace;
			PSID gSid = (PSID)&ace->SidStart;
			
			if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL) {
				int err = GetLastError();
				if (err == 122) {
					uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
					uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
					if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
					{
						exit(1);
					}
					err = 0;
				}
			}
			printf("������������ %d: %s\n", i + 1, uname);
		}
		free(uname);
		free(uname2);
		scanf("%d", &user);
		GetAce(Dacl, user - 1, &getace);
		ace = (PACCESS_ALLOWED_ACE)getace;
		PSID gSid = (PSID)&ace->SidStart;
		return gSid;
	}
	return NULL;
}

DWORD getMask(DWORD* aMask)
{
	int sss = 0;
snova:
	printf("�������� �����:\n");
	printf("1 - ������ ������\n");
	printf("2 - ��������\n");
	printf("3 - ������ �����\n");
	scanf("%d", &sss);
	switch (sss)
	{
	case(1):
	{
		*aMask |= FILE_ALL_ACCESS;
		break;
	}
	case(2):
	{
		*aMask |= DELETE;
		break;
	}
	case(3):
	{
		*aMask |= FILE_GENERIC_READ;
		break;
	}
	default:
		printf("�� ���������� ����� �������\n");
		goto snova;
	}
	return *aMask;
}

void ShowAttrs(ACCESS_ALLOWED_ACE* ace)
{

	printf("\n");
	if ((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
		printf("������ ������\n");
	if ((ace->Mask & DELETE) == DELETE)
		printf("�������� �����\n");
	if ((ace->Mask & WRITE_DAC) == WRITE_DAC)
		printf("��������� ���������\n");
	if ((ace->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
		printf("������ �����\n");
	if ((ace->Mask & FILE_EXECUTE) == FILE_EXECUTE)
		printf("������ ����\n");
	return;
}

int ReadACE(char* fileName) {
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	LPVOID getace;
	PACCESS_ALLOWED_ACE ace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	SID_NAME_USE puse;
	int Nace = 0;
	if (GetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {

		int countAces = Dacl->AceCount;

		if (countAces == 0) {
			printf("���������� ���\n");
			return 0;
		}
		else {
			for (int i = 0; i < countAces; i++) {
				GetAce(Dacl, i, &getace);
				ace = (PACCESS_ALLOWED_ACE)getace;
				PSID gSid = (PSID)&ace->SidStart;

				if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL) {
					int err = GetLastError();
					if (err == 122) {
						uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
						uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
						if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
						{
							exit(1);
						}
						err = 0;
					}
				}
				printf("ACE %d: %s - ", i + 1, uname);
				if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
				{
					printf("���������\n");
				}
				else
				{
					printf("���������\n");
				}
			}
			printf("�������� ACE\n");
			scanf("%d", &Nace);
			GetAce(Dacl, Nace - 1, &getace);
			ace = (PACCESS_ALLOWED_ACE)getace;
			ShowAttrs(ace);
			free(uname);
			free(uname2);
		}
	}
}

int CreateACE(char* fileName) {
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	int pr = 0;
	if (GetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {
		
		int countAces = Dacl->AceCount;

		PSID gSid = PrintUsers();
		
		printf("��������� ��� ���������(1/0)\n");
		scanf("%d", &pr);

		DWORD aMask = 0;
		EXPLICIT_ACCESS addAce;
		ZeroMemory(&addAce, sizeof(EXPLICIT_ACCESS));

		addAce.grfAccessPermissions = getMask(&aMask);

		if (pr == 1) {
			addAce.grfAccessMode = GRANT_ACCESS;
		}
		else {
			addAce.grfAccessMode = DENY_ACCESS;
		}
		addAce.grfInheritance = NO_INHERITANCE;
		addAce.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		addAce.Trustee.ptstrName = (LPCH)gSid;

		PACL NDacl = NULL;
		if (SetEntriesInAclA(1, &addAce, Dacl, &NDacl) != ERROR_SUCCESS) {
			int err = GetLastError();
			printf("������\n");
		}
		else
		{
			if (SetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NDacl, NULL) != ERROR_SUCCESS) {
				int err = GetLastError();
				printf("������");

			}

		}
		if (NDacl != NULL)
			LocalFree((HLOCAL)NDacl);
		if (Sec != NULL)
			LocalFree((HLOCAL)Sec);
	}
	else
	{
		return 1;
	}
	printf("������� ������\n\n");
	return 0;
}

int ChangeACE(char* fileName) {
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	LPVOID getace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	SID_NAME_USE puse;
	PACCESS_ALLOWED_ACE ace;
	int nace = 0;
	if (GetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {
		int countAces = Dacl->AceCount;

		if (countAces == 0) {
			printf("���������� ���\n");
			return 0;
		}
		else {
			for (int i = 0; i < countAces; i++) {
				GetAce(Dacl, i, &getace);
				ace = (PACCESS_ALLOWED_ACE)getace;
				PSID gSid = (PSID)&ace->SidStart;

				if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL) {
					int err = GetLastError();
					if (err == 122) {
						uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
						uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
						if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
						{
							exit(1);
						}
						err = 0;
					}
				}
				printf("ACE %d: %s - ", i + 1, uname);
				if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
				{
					printf("���������\n");
				}
				else
				{
					printf("���������\n");
				}
			}
			printf("�������� ACE\n");
			scanf("%d", &nace);
			GetAce(Dacl, nace - 1, &getace);
			ace = (PACCESS_ALLOWED_ACE)getace;
			DWORD newMask = 0;
			printf("��������� ��� ���������(1/0)\n");
			int pr;
			scanf("%d", &pr);
			if (pr == 1) {
				ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
			}
			else {
				ace->Header.AceType = ACCESS_DENIED_ACE_TYPE;
				ace->Header.AceFlags = 0;
			}
			ace->Mask = getMask(&newMask);
			if (SetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS)
			{
				printf("������� ��������!");
			}
		}
	}
	return 0;
}

int DeleteACE(char* fileName) {
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	LPVOID getace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	SID_NAME_USE puse;
	PACCESS_ALLOWED_ACE ace;
	int nace = 0;
	if (GetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {
		int countAces = Dacl->AceCount;

		if (countAces == 0) {
			printf("���������� ���");
			return 0;
		}
		else {
			for (int i = 0; i < countAces; i++) {
				GetAce(Dacl, i, &getace);
				ace = (PACCESS_ALLOWED_ACE)getace;
				PSID gSid = (PSID)&ace->SidStart;

				if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL) {
					int err = GetLastError();
					if (err == 122) {
						uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
						uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
						if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
						{
							exit(1);
						}
						err = 0;
					}
				}
				printf("ACE %d: %s - ", i + 1, uname);
				if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
				{
					printf("���������\n");
				}
				else
				{
					printf("���������\n");
				}
			}
			printf("������� ACE\n");
			scanf("%d", &nace);
			if (DeleteAce(Dacl, nace - 1) != 0) {
				if (SetNamedSecurityInfoA(fileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS) {
					printf("������� ������\n");
				}
				return 0;
			}
			else {
				printf("ACE �� ������");
				return 0;
			}
		}
	}
	return 0;
}

int main() {
	SetConsoleCP(1251); 
	SetConsoleOutputCP(1251);
	int comand = 0;
	char fileName[MAX_PACKAGE_NAME] = { 0 };
	printf("������� �������:\n1 - ������� ACE\n2 - ��������� ACE\n3 - ������������ ACE\n4 - ������� ACE\n");
	scanf("%d", &comand);
	switch (comand) {
	case 1:
		printf("������� ��� �����:\n");
		scanf("%s", fileName);
		CreateACE(fileName);
		break;
	case 2:
		printf("������� ��� �����:\n");
		scanf("%s", fileName);
		ReadACE(fileName);
		break;
	case 3:
		printf("������� ��� �����:\n");
		scanf("%s", fileName);
		ChangeACE(fileName);
		break;
	case 4:
		printf("������� ��� �����:\n");
		scanf("%s", fileName);
		DeleteACE(fileName);
		break;
	}
	return 0;
}