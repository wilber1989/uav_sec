#ifndef _PRJ_DIR_FILE_H
#define _PRJ_DIR_FILE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct wbacDataBlock
{
	uint8_t *data;
	int length;
} wbacDataBlock;

wbacDataBlock *wbac_cbc_encrypt(wbacDataBlock *input, uint8_t *iv);
wbacDataBlock *wbac_cbc_decrypt(wbacDataBlock *input, uint8_t *iv);
void dataBlockDestory(wbacDataBlock *dataptr);
void dataBlockInit(wbacDataBlock **dataptr, uint8_t *arr, int length);
#endif

