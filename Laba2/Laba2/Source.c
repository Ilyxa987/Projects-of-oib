#define _CRT_SECURE_NO_WARNINGS
#define ACL_SIZE = 1024;
#include <stdio.h>
#include <AclAPI.h>
#include <locale.h>

PACL PrintAces(char* name, int what, PACCESS_ALLOWED_ACE* aces, int* how, PSID* acesid)
{
	PACL Dacl = NULL;
	PSID GetSid = NULL;
	PSECURITY_DESCRIPTOR Sec;
	LPVOID getace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	PACCESS_ALLOWED_ACE ace;
	SID_NAME_USE puse;
	int hh = 0;

	//��������� ����� ����������� ������������ ��� ����� name
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) != ERROR_SUCCESS) {
		return 0;
	}
	//���� ������� ���������� ��� ����������� ��������� ��� �������� ACE
	if (how != NULL && *how == 2)
	{
		printf("\n�������� ������������\n\n");
	}

	// � ����� ������� ��� ACE, ������������ � ���������� ����� ACL
	for (int i = 0; i < Dacl->AceCount; i++)
	{
		GetAce(Dacl, i, &getace);            // �������� ��������� �� ACE
		ace = (PACCESS_ALLOWED_ACE)getace;   // ��������� �� ACE
		PSID gSid = (PSID)&ace->SidStart;    // �������� ��� ACE
		if (what == 3)                       //���� ����� ������� ����� ACE, ��������� ���� � ������ ��� ����������� �������������
		{
			acesid[i] = gSid;
		}
		else if (how != NULL && *how == 404)     // ���� ���������� �������� ����� ACE � ��������� �������� ��� ������-���� �� ���
		{
			if (aces != NULL)
			{
				aces[i] = ace;                   // ������ ��������� � ������
			}
			hh++;                                // ������� ���-�� ACE
		}
		// ��������� ����� ACE
		if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL)
		{
			int err = GetLastError();
			// ���� ����� ������� ���, �������� ����������� ��� ���� ������
			if (err == 122) {
				uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
				uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
				// ���� ������ ��� ��� �� ����������, ������� �� ���������
				if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
				{
					exit(1);
				}
				err = 0;
			}
		}
		// ������� ACE �� �����
		printf("������������ %d: %s - ", i + 1, uname);
		if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			printf("���������\n");
		}
		else
		{
			printf("���������\n");
		}

	}
	free(uname);
	free(uname2);
	if (what == 1 || (how != NULL && *how == 404))
	{
		*how = hh;                                               // ���������� ���-�� �������
	}
	return Dacl;
}

void ShowAttrs(ACCESS_ALLOWED_ACE* ace)
{

	printf("\n");
	// ��������� �����,������ �� ACCESS_MASK ��������� �����, ������������ � ACE
	if ((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
		printf("������ ������\n");
	if ((ace->Mask & DELETE) == DELETE)
		printf("�������� �����\n");
	if ((ace->Mask & WRITE_DAC) == WRITE_DAC)
		printf("��������� ���������\n");
	if ((ace->Mask & FILE_READ_DATA) == FILE_READ_DATA)
		printf("������ �����\n");
	if ((ace->Mask & FILE_EXECUTE) == FILE_EXECUTE)
		printf("������ ����\n");
	return;
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

	//��������� ����� � ACE ��������� ACCESS_MASK
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
		*aMask |= FILE_READ_DATA;
		break;
	}
	default:
		printf("�� ���������� ����� �������\n");
		goto snova;
	}


	return *aMask;
}

void changeACE(char* name)
{
	PACL Dacl = NULL;
	PSID GetSid = NULL;
	PSECURITY_DESCRIPTOR Sec;
	LPVOID getace;
	LPSTR uname = NULL;
	LPSTR uname2 = NULL;
	DWORD size1 = 0;
	DWORD size2 = 0;
	PACCESS_ALLOWED_ACE ace;
	int who;
	// �������� ����� ����������� ������������ ��� �����
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS)
	{
	again:
		printf("�������� ������������: (0 - �����)\n\n");
		int* wh;
		int z = 404;
		wh = &z;
		// �������� �������, ���������� ����� ACE
		Dacl = PrintAces(name, 0, NULL, wh, NULL);
		getace = NULL;
		scanf("%d", &who);
		if (who == 0)
		{
			return;
		}
		else if (who > *wh)
		{
			printf("�� ���������� ������ ������������\n");
			goto again;
		}
		//��������� ��������� �� ��������� ACE
		GetAce(Dacl, who - 1, &getace);
		ace = (PACCESS_ALLOWED_ACE)getace;
		DWORD Amask = 0;
		// �������� �������, �������� ACE, ��������� ACCESS_MASK
		ace->Mask = getMask(&Amask);
		// ��������� ���������� � ������������ �����, ����� ��������� ����� ACE
		if (SetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS)
		{
			printf("������� ��������!\n\n");
		}

	}
	//����������� ������
	if (Dacl != NULL)
	{
		LocalFree((HLOCAL)Dacl);
	}
	if (Sec != NULL)
	{
		LocalFree((HLOCAL)Sec);
	}
}

int Delete(char* name)
{
	int z = 2;
	int* who;
	who = &z;
	// ������� ����� ACE �� �����
	PACL Dacl = PrintAces(name, 0, NULL, who, NULL);
	if (Dacl == 0)
	{
		printf("���� �� ������\n");
		return 1;
	}
	scanf("%d", who);
	int q;
	// ������� ��������� ACE
	if (q = DeleteAce(Dacl, *who - 1) != 0)
	{

		if (SetNamedSecurityInfo(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS)
		{
			printf("������� ������\n");
			if (Dacl != NULL)
			{
				LocalFree((HLOCAL)Dacl);
			}
			return 0;
		}
	}
	else
	{

		printf("�������� ��������\n");
		if (Dacl != NULL)
		{
			LocalFree((HLOCAL)Dacl);
		}
		return 1;
	}
	return 0;

}

int ObjInf(char* name)
{
	PSID GetSid = NULL;
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR Sec = NULL;
	PSID sids[20];
	// ��������� ����� ����������� ������������ ��� �����
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {

		int cntofus = Dacl->AceCount; // �������� ���������� ������� � ACL

		// ������� ������ �� �����

		PrintAces(name, 3, NULL, NULL, sids);
	povtor:
		printf("�������� ������������(0 - �����)\n");
		int us;
		int ad;
		scanf("%d", &us);
		if (us == 0)
		{
			return 0;
		}
		else if (us > cntofus)
		{
			printf("������ ������������ �� ����������\n");
			goto povtor;
		}
		printf("��������� ��� ���������? (1/0)\n");
		scanf("%d", &ad);
		DWORD aMask = 0;


		// ���������� ���������� �������� �������, ����� ��������������� �������� SetEntriesInAcl

		EXPLICIT_ACCESS addAce;
		ZeroMemory(&addAce, sizeof(EXPLICIT_ACCESS));
		//������������� ����� �������
		addAce.grfAccessPermissions = getMask(&aMask);
		// � ����������� �� ������ ������������, ���������� �����������/����������� �������� ACE
		if (ad == 0)
		{
			addAce.grfAccessMode = DENY_ACCESS;
		}
		else
		{
			addAce.grfAccessMode = GRANT_ACCESS;
		}
		// �� ���������� ������������
		addAce.grfInheritance = NO_INHERITANCE;
		// ������������� �� ����
		addAce.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		// ��������� ���
		addAce.Trustee.ptstrName = (LPCH)sids[us - 1];
		PACL NDacl = NULL;
		// ���������  ACE � ACL
		if (SetEntriesInAclA(1, &addAce, Dacl, &NDacl) != ERROR_SUCCESS) {
			int err = GetLastError();
			printf("������\n");
		}
		else
		{
			// ��������� ���������� ������������ ��� ���������� ������ ACL
			if (SetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NDacl, NULL) != ERROR_SUCCESS) {
				int err = GetLastError();
				printf("������");

			}

		}
		// ����������� ������
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


int main()
{
	setlocale(LC_ALL, "Russian");
	char name[MAX_PACKAGE_NAME];
	printf("������� ��� �����: ");
	scanf("%s", name);
	while (1)
	{
		printf("\n1 - �������� ACE\n2 - ������ ACE\n3 - ������� ACE\n4 - ������������ ACE\n0 - ��������� �����\n");
		int sss;
		scanf("%d", &sss);
		switch (sss)
		{
		case(1):
		{
			if (ObjInf(name) == 1)
			{
				printf("���� �� ������\n");
			}
			break;
		}
		case(2):
		{
			int* wh;
			int z = 404;
			wh = &z;
			ACCESS_ALLOWED_ACE* aces[20];
			if (PrintAces(name, 1, aces, wh, NULL) == 0)
			{
				printf("���� �� ������\n");
				break;
			}

			printf("�������� ������������ ��� ������ ��������� (0 - �����)\n");
			int which;
			scanf("%d", &which);
			if (which == 0)
			{
				break;
			}
			else if (which > *wh)
			{
				printf("������ ������������ ���\n");
				break;
			}
			ShowAttrs(aces[which - 1]); // ������� �������� ��� ���������� ACE
		}
		break;
		case(3):
			Delete(name);

			break;
		case(4):
			changeACE(name);
			break;
		case(0):
			exit(0);
		default:
			printf("�������� �������\n");
			break;
		}
	}
	system("Pause");
	exit(0);
}