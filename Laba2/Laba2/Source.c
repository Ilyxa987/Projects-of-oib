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

	//извлекаем копию дескриптора безопасности для файла name
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) != ERROR_SUCCESS) {
		return 0;
	}
	//если функция вызывается для отображения доступных для удаления ACE
	if (how != NULL && *how == 2)
	{
		printf("\nВыберите пользователя\n\n");
	}

	// в цикле выводим все ACE, содержащиеся в полученном ранее ACL
	for (int i = 0; i < Dacl->AceCount; i++)
	{
		GetAce(Dacl, i, &getace);            // получаем указатель на ACE
		ace = (PACCESS_ALLOWED_ACE)getace;   // указатель на ACE
		PSID gSid = (PSID)&ace->SidStart;    // получаем сид ACE
		if (what == 3)                       //если нужно создать новый ACE, сохраняем сиды в массив для дальнейшего использования
		{
			acesid[i] = gSid;
		}
		else if (how != NULL && *how == 404)     // если необходимо получить набор ACE и прочитать атрибуты для какого-либо из них
		{
			if (aces != NULL)
			{
				aces[i] = ace;                   // вносим указатель в массив
			}
			hh++;                                // считаем кол-во ACE
		}
		// получение имени ACE
		if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse) || uname == NULL)
		{
			int err = GetLastError();
			// если буфер слишком мал, выделяем достаточную под него память
			if (err == 122) {
				uname = (TCHAR*)malloc(size1 * sizeof(TCHAR));
				uname2 = (TCHAR*)malloc(size2 * sizeof(TCHAR));
				// если памяти все еще не достаточно, выходим из программы
				if (!LookupAccountSidA(NULL, gSid, uname, &size1, uname2, &size2, &puse))
				{
					exit(1);
				}
				err = 0;
			}
		}
		// выводим ACE на экран
		printf("Пользователь %d: %s - ", i + 1, uname);
		if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			printf("Разрешить\n");
		}
		else
		{
			printf("Запретить\n");
		}

	}
	free(uname);
	free(uname2);
	if (what == 1 || (how != NULL && *how == 404))
	{
		*how = hh;                                               // возвращаем кол-во записей
	}
	return Dacl;
}

void ShowAttrs(ACCESS_ALLOWED_ACE* ace)
{

	printf("\n");
	// использую маску,взятую из ACCESS_MASK считываем права, содержащиеся в ACE
	if ((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
		printf("Полный доступ\n");
	if ((ace->Mask & DELETE) == DELETE)
		printf("Удаление файла\n");
	if ((ace->Mask & WRITE_DAC) == WRITE_DAC)
		printf("Изменение атрибутов\n");
	if ((ace->Mask & FILE_READ_DATA) == FILE_READ_DATA)
		printf("Чтение файла\n");
	if ((ace->Mask & FILE_EXECUTE) == FILE_EXECUTE)
		printf("Запуск файл\n");
	return;
}

DWORD getMask(DWORD* aMask)
{
	int sss = 0;
snova:
	printf("Выберите права:\n");
	printf("1 - Полный доступ\n");
	printf("2 - Удаление\n");
	printf("3 - Чтение файла\n");
	scanf("%d", &sss);

	//добавляем права в ACE используя ACCESS_MASK
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
		printf("Не существует такой команды\n");
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
	// получаем копию дескриптора безопасности для файла
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS)
	{
	again:
		printf("Выберите пользователя: (0 - выход)\n\n");
		int* wh;
		int z = 404;
		wh = &z;
		// вызываем функцию, печатующую набор ACE
		Dacl = PrintAces(name, 0, NULL, wh, NULL);
		getace = NULL;
		scanf("%d", &who);
		if (who == 0)
		{
			return;
		}
		else if (who > *wh)
		{
			printf("Не существует такого пользователя\n");
			goto again;
		}
		//сохраняем указатель на выбранный ACE
		GetAce(Dacl, who - 1, &getace);
		ace = (PACCESS_ALLOWED_ACE)getace;
		DWORD Amask = 0;
		// вызываем функцию, меняющую ACE, используя ACCESS_MASK
		ace->Mask = getMask(&Amask);
		// обновляем информацию о безопасности файла, чтобы применить новый ACE
		if (SetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS)
		{
			printf("Успешно изменено!\n\n");
		}

	}
	//освобождаем память
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
	// выводим набор ACE на экран
	PACL Dacl = PrintAces(name, 0, NULL, who, NULL);
	if (Dacl == 0)
	{
		printf("Файл не найден\n");
		return 1;
	}
	scanf("%d", who);
	int q;
	// удаляем выбранный ACE
	if (q = DeleteAce(Dacl, *who - 1) != 0)
	{

		if (SetNamedSecurityInfo(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS)
		{
			printf("Успешно удален\n");
			if (Dacl != NULL)
			{
				LocalFree((HLOCAL)Dacl);
			}
			return 0;
		}
	}
	else
	{

		printf("Возникли проблемы\n");
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
	// извлекаем копию дескриптора безопасности для файла
	if (GetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, &GetSid, &Dacl, NULL, &Sec) == ERROR_SUCCESS) {

		int cntofus = Dacl->AceCount; // получаем количество записей в ACL

		// выводим список на экран

		PrintAces(name, 3, NULL, NULL, sids);
	povtor:
		printf("Выберите пользователя(0 - выход)\n");
		int us;
		int ad;
		scanf("%d", &us);
		if (us == 0)
		{
			return 0;
		}
		else if (us > cntofus)
		{
			printf("Такого пользователя не существует\n");
			goto povtor;
		}
		printf("Разрешить или запретить? (1/0)\n");
		scanf("%d", &ad);
		DWORD aMask = 0;


		// определяем информацию контроля доступа, чтобы воспользоваться функцией SetEntriesInAcl

		EXPLICIT_ACCESS addAce;
		ZeroMemory(&addAce, sizeof(EXPLICIT_ACCESS));
		//устанавливаем права доступа
		addAce.grfAccessPermissions = getMask(&aMask);
		// в зависимости от выбора пользователя, определяем разрешающий/запрещающий характер ACE
		if (ad == 0)
		{
			addAce.grfAccessMode = DENY_ACCESS;
		}
		else
		{
			addAce.grfAccessMode = GRANT_ACCESS;
		}
		// не испьльзуем наследование
		addAce.grfInheritance = NO_INHERITANCE;
		// идентификация по сиду
		addAce.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		// указываем сид
		addAce.Trustee.ptstrName = (LPCH)sids[us - 1];
		PACL NDacl = NULL;
		// добавляем  ACE в ACL
		if (SetEntriesInAclA(1, &addAce, Dacl, &NDacl) != ERROR_SUCCESS) {
			int err = GetLastError();
			printf("Ошибка\n");
		}
		else
		{
			// обновляем дескриптор безопасности для применения нового ACL
			if (SetNamedSecurityInfoA(name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NDacl, NULL) != ERROR_SUCCESS) {
				int err = GetLastError();
				printf("Ошибка");

			}

		}
		// освобождаем память
		if (NDacl != NULL)
			LocalFree((HLOCAL)NDacl);
		if (Sec != NULL)
			LocalFree((HLOCAL)Sec);
	}
	else
	{

		return 1;
	}
	printf("Успешно создан\n\n");
	return 0;
}


int main()
{
	setlocale(LC_ALL, "Russian");
	char name[MAX_PACKAGE_NAME];
	printf("Введите имя файла: ");
	scanf("%s", name);
	while (1)
	{
		printf("\n1 - Добавить ACE\n2 - Читать ACE\n3 - Удалить ACE\n4 - Перезаписать ACE\n0 - Завершить рабоу\n");
		int sss;
		scanf("%d", &sss);
		switch (sss)
		{
		case(1):
		{
			if (ObjInf(name) == 1)
			{
				printf("Файл не найден\n");
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
				printf("Файл не найден\n");
				break;
			}

			printf("Выберите пользователя для чтения атрибутов (0 - назад)\n");
			int which;
			scanf("%d", &which);
			if (which == 0)
			{
				break;
			}
			else if (which > *wh)
			{
				printf("Такого пользователя нет\n");
				break;
			}
			ShowAttrs(aces[which - 1]); // выводим атрибуты для указанного ACE
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
			printf("Неверная команда\n");
			break;
		}
	}
	system("Pause");
	exit(0);
}