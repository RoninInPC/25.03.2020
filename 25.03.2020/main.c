#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>
int main() {
	printf("Write number. Number 1 - exc 1, Number 2 -exc 2\n");
	int exc;
	scanf_s("%d", &exc);
	if (exc == 1) {
		printf("write password >= 20 symbols: Min 10 0-9 numbers and 2 special symbol\n");
		int x;
		int k = 0;
		char* arr[1000];
		while (1) {
			x = getch();
			if ((x >= 48 && x <= 57) || (x >= 65 && x <= 90) || (x >= 97 && x <= 122) || (x >= 33 && x <= 38)) {
				arr[k] = x;
					k++;
			}
			if (x == 8) {
				k--;
			}
			system("cls");

			for (int i = 0; i < k; i++) {
				printf("*");
			}
			if (x == 13) {
				break;
			}
		}
		printf("\n");
		int k2 = 0;
		int k1 = 0;
		for (int i = 0; i < k; i++) {
			if (arr[i] >= 33 && arr[i] <= 38) {
				k2++;
			}
			if (arr[i] >= '0' && arr[i] <= '9') {
				k1++;
			}
		}
		if (k2 < 2 || k1 < 10 || k < 20) {
			printf("You have wrong password\n");
		}
		else
			printf("You have hard password\n");
	}
	else
	{
		LPUSER_INFO_0 pBuf = NULL;
		LPUSER_INFO_0 pTmpBuf;
		DWORD dwLevel = 0;
		DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
		DWORD dwEntriesRead = 0;
		DWORD dwTotalEntries = 0;
		DWORD dwResumeHandle = 0;
		DWORD i;
		DWORD dwTotalCount = 0;
		NET_API_STATUS nStatus;
		LPTSTR pszServerName = NULL;
		do {
			nStatus = NetUserEnum((LPCWSTR)pszServerName, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
			if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
			{
				if ((pTmpBuf = pBuf) != NULL)
				{
					for (i = 0; (i < dwEntriesRead); i++)
					{
						assert(pTmpBuf != NULL);

						if (pTmpBuf == NULL)
						{
							fprintf(stderr, "An access violation has occurred\n");
							break;
						}
						wprintf(L"\t-- %s\n", pTmpBuf->usri0_name);
						pTmpBuf++;
						dwTotalCount++;
					}
				}
			}
			else
				fprintf(stderr, "A system error has occurred: %d\n", nStatus);
			if (pBuf != NULL)
			{
				NetApiBufferFree(pBuf);
				pBuf = NULL;
			}
		}
		while (nStatus == ERROR_MORE_DATA);
		printf("Total %d users\n", dwTotalCount);
	}
	return 0;
}