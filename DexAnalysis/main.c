#include <stdio.h>
#include "DexFile.h"
#include <string.h>

int fp_move(FILE * fp, int offset);
void help();
void dex_header(FILE * fp);
void dex_strings(FILE * fp, int page, int limit);
void dex_types(FILE * fp);

DexTypeId * get_dextypes(FILE * fp, u4 offset, int size);
int get_string_size_by_id(FILE *fp, DexStringId * dexstrings, int id);
DexStringId * get_dexstrings(FILE * fp, u4 offset, int size);
bool get_string_by_id(FILE *fp, DexStringId * dexstrings, int id, char * buff);

DexHeader* get_dex__header(FILE * fp);

int main(int argc, char* argv[]) {

	/*if (!strcmp(argv[1], "-help")) {
		help();
		exit(0);
	}

	if (argc < 3)
	{
		printf("invalid arguments\n");
		exit(0);
	}*/

	FILE *fp;
	errno_t err = 0;


	//err = fopen_s(&fp, argv[2], "rb");
	err = fopen_s(&fp, "D:/source/repos/DexAnalysis/Debug/classes.dex", "rb");
	if (NULL == fp)
	{
		printf("open file fail\n");
		exit(0);
	}
	printf("-----------------------------------------------------------------------------------------------------\n");
	dex_types(fp);
	/*if (!strcmp(argv[1], "-h")) {
		dex_header(fp);
	}
	else if (!strcmp(argv[1], "-s")) {
		dex_strings(fp, 2, 20);
	}
	else if (!strcmp(argv[1], "-t")) {
		dex_types(fp);
	}
	else if (!strcmp(argv[1], "-l")) {
	}
	else if (!strcmp(argv[1], "-r")) {
	}*/
	//help();

	if (fp) {
		err = fclose(fp);
		if (err == 0) {
			printf("-----------------------------------------------------------------------------------------------------\n");
			//printf("The file closed\n");
		}
		else {
			printf("The file was not closed\n");
		}
	}
	return 0;
}

//�������ͱ�
void dex_types(FILE * fp) {
	//�õ�dexͷ
	DexHeader* dex_header = get_dex__header(fp);
	if (dex_header == NULL) {
		printf("dex_header error\n");
		return;
	}
	//�õ��ַ�����
	DexStringId * dexstrings = get_dexstrings(fp, dex_header->stringIdsOff, dex_header->stringIdsSize);
	if (dexstrings == NULL) {
		printf("dexstrings error\n");
		free(dex_header);
		return;
	}

	//�õ����ͱ�
	DexTypeId * dextypes = get_dextypes(fp, dex_header->typeIdsOff, dex_header->typeIdsSize);
	if (dextypes == NULL) {
		printf("dextypes error\n");
		free(dexstrings);
		free(dex_header);
		return;
	}

	for (int typeIndex = 0; typeIndex < dex_header->typeIdsSize; typeIndex++)
	{
		int stringIdx = dextypes[typeIndex].descriptorIdx;
		int string_length = get_string_size_by_id(fp, dexstrings, stringIdx) + 1;
		char * temp = (char *)malloc(string_length);
		memset(temp, 0, string_length);

		if (temp == NULL) {
			goto end;
		}
		bool result = get_string_by_id(fp, dexstrings, stringIdx, temp);
		if (!result) {
			free(temp);
			goto end;
		}
		printf("%d\t  %s \n", typeIndex,temp);
		free(temp);
	}

end:
	free(dextypes);
	free(dexstrings);
	free(dex_header);
}

//�����ַ�����
/*
	page ҳ��
	limit ÿҳ������
*/
void dex_strings(FILE * fp, int page, int limit) {
	//�õ�dexͷ
	DexHeader* dex_header = get_dex__header(fp);

	u4 stringIdsOff = dex_header->stringIdsOff;
	u4 stringIdsSize = dex_header->stringIdsSize;

	printf("�ַ��������Ϊ%#X ��СΪ%d\n", stringIdsOff, stringIdsSize);

	//��ʼ����
	int page_start = (page - 1)*limit;
	//��������
	int page_end = page_start + limit;
	if (page_start > stringIdsSize - 1) {
		printf("page out of stringIdsSize\n");
		return;
	}
	page_end = page_end < stringIdsSize - 1 ? page_end : stringIdsSize - 1;

	DexStringId * dexstrings = (DexStringId *)malloc(sizeof(DexStringId)*limit);
	if (dexstrings == NULL) {
		printf("dexstrings malloc error\n");
		free(dex_header);
	}
	memset(dexstrings, 0, sizeof(sizeof(DexStringId)*limit));

	int result = 0;
	//��ȡ����
	int move_off = stringIdsOff + sizeof(DexStringId)* page_start;
	fp_move(fp, move_off);
	result = fread(dexstrings, sizeof(DexStringId), limit, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(dex_header);
		free(dexstrings);
		return;
	}


	for (int i = 0; page_start < page_end; i++, page_start++)
	{
		fp_move(fp, dexstrings[i].stringDataOff);
		int size = 0;

		result = fread(&size, 1, 1, fp);
		if (result == 0) {
			printf("READ ERROR\n");
			free(dex_header);
			free(dexstrings);
			return;
		}

		char * dex_string = (char *)malloc(size + 1);
		if (dex_string == NULL) {
			printf("dex_string malloc ERROR\n");
			free(dex_header);
			free(dexstrings);
			return;
		}
		result = fread(dex_string, size + 1, 1, fp);
		if (result == 0) {
			printf("READ ERROR\n");
			free(dex_header);
			free(dexstrings);
			return;
		}

		printf("[%-2d]  %#8.08X  %4d %s\n", page_start, dexstrings[i].stringDataOff, size, dex_string);
		free(dex_string);

	}


	free(dexstrings);
	free(dex_header);
}

int get_string_size_by_id(FILE *fp, DexStringId * dexstrings, int id) {
	fp_move(fp, dexstrings[id].stringDataOff);
	int result = 0;
	int size = 0;
	result = fread(&size, 1, 1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		return -1;
	}
	return size;
}

//�õ��ַ���ָ��id�ַ���
bool get_string_by_id(FILE *fp, DexStringId * dexstrings, int id, char * buff) {
	u4 offset = dexstrings[id].stringDataOff;
	fp_move(fp, offset);
	int result = 0;
	int size = 0;

	result = fread(&size, 1, 1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		return false;
	}

	result = fread(buff, 1, size+1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		return false;
	}

	return true;
}

//�õ��ַ����� �ͷ��ڴ�
DexStringId * get_dexstrings(FILE * fp, u4 offset, int size) {
	DexStringId * dexstrings = (DexStringId *)malloc(sizeof(DexStringId)*size);
	if (dexstrings == NULL) {
		printf("dexstrings malloc error\n");
		return NULL;
	}
	memset(dexstrings, 0, sizeof(sizeof(DexStringId)*size));

	int result = 0;
	//��ȡ����
	fp_move(fp, offset);
	result = fread(dexstrings, sizeof(DexStringId), size, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(dexstrings);
		return NULL;
	}
	return dexstrings;
}

//�õ����ͱ� �ͷ��ڴ�
DexTypeId * get_dextypes(FILE * fp, u4 offset, int size) {
	DexStringId * dextypes = (DexTypeId *)malloc(sizeof(DexTypeId)*size);
	if (dextypes == NULL) {
		printf("dextypes malloc error\n");
		return NULL;
	}
	memset(dextypes, 0, sizeof(sizeof(DexTypeId)*size));

	int result = 0;
	//��ȡ����
	fp_move(fp, offset);
	result = fread(dextypes, sizeof(DexTypeId), size, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(dextypes);
		return NULL;
	}
	return dextypes;
}

//����header
void dex_header(FILE * fp) {
	//�õ�dex
	DexHeader* dex_header = get_dex__header(fp);
	char*  magic = "dex\n035\0";
	if (memcmp(dex_header->magic, magic, 8)) {
		printf("Ŀ�겻��һ���Ϸ���dex�ļ�\n");
		return;
	}

	printf("%-15s dex\\n035\\0\n", "magic:");

	printf("%-15s %#X\n", "checksum:", dex_header->checksum);

	printf("%-15s 0X", "signature:");
	for (size_t i = 0; i < kSHA1DigestLen; i++)
	{
		printf("%X", dex_header->signature[i]);
	}
	printf("\n");
	printf("%-15s %#X\n", "fileSize:", dex_header->fileSize);
	printf("%-15s %#X\n", "headerSize:", dex_header->headerSize);
	printf("%-15s %#X\n", "endianTag:", dex_header->endianTag);


	printf("%-15s %#X\n", "linkSize:", dex_header->linkSize);
	printf("%-15s %#X\n", "linkOff:", dex_header->linkOff);
	printf("%-15s %#X\n", "mapOff:", dex_header->mapOff);
	printf("%-15s %#X\n", "stringIdsSize:", dex_header->stringIdsSize);
	printf("%-15s %#X\n", "stringIdsOff:", dex_header->stringIdsOff);
	printf("%-15s %#X\n", "typeIdsSize:", dex_header->typeIdsSize);
	printf("%-15s %#X\n", "typeIdsOff:", dex_header->typeIdsOff);
	printf("%-15s %#X\n", "protoIdsSize:", dex_header->protoIdsSize);
	printf("%-15s %#X\n", "protoIdsOff:", dex_header->protoIdsOff);
	printf("%-15s %#X\n", "fieldIdsSize:", dex_header->fieldIdsSize);
	printf("%-15s %#X\n", "fieldIdsOff:", dex_header->fieldIdsOff);
	printf("%-15s %#X\n", "methodIdsSize:", dex_header->methodIdsSize);
	printf("%-15s %#X\n", "methodIdsOff:", dex_header->methodIdsOff);
	printf("%-15s %#X\n", "classDefsSize:", dex_header->classDefsSize);
	printf("%-15s %#X\n", "classDefsOff:", dex_header->classDefsOff);
	printf("%-15s %#X\n", "dataSize:", dex_header->dataSize);
	printf("%-15s %#X\n", "dataOff:", dex_header->dataOff);


	free(dex_header);
}

//�õ�dexͷ
DexHeader* get_dex__header(FILE * fp) {
	fp_move(fp, 0);
	DexHeader *dex_header = (DexHeader*)malloc(sizeof(DexHeader));
	memset(dex_header, 0, sizeof(DexHeader));

	if (dex_header == NULL) {
		printf("dex_header malloc failed\n");
		return NULL;
	}

	int result = 0;
	//��ȡ����
	result = fread(dex_header, sizeof(DexHeader), 1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(dex_header);
		return NULL;
	}
	return dex_header;
}


//�ƶ�fp  ʧ�ܷ���0
int fp_move(FILE * fp, int offset) {
	rewind(fp);
	int result;

	result = fseek(fp, offset, SEEK_SET);
	if (result != 0) {
		printf("fp_move ERROR \n");
		return 0;
	}
}

//��ӡ������Ϣ
void help()
{
	printf("����Shark Chilli�Ľ�����0.0,�����ʿ��Է��͵��ҵ�����:1243596620@qq.com\n");
	printf("-h            :ͷ����Ϣ\n");
	printf("-S            :��������Ϣ\n");
	printf("-s            :���ű���Ϣ\n");
	printf("-l            :����ͷ��Ϣ\n");
	printf("-r            :�ض�λ����Ϣ\n");
}