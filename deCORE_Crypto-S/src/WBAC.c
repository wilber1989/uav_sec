#include "../include/WBAC.h"
#include "../include/Boxes.h"

uint8_t state[4][4] = {0};

//convert 128-bit to state array
void w128b_2_State(uint8_t *input, uint8_t state[4][4])
{
    int r, c;
    for (r = 0; r < 4; r++)
    {
	for (c = 0; c < 4; c++)
	{
	    state[r][c] = input[r + c * 4];
	}
    }
}

//ShiftRows operation
void ShiftRows(uint8_t state[][4])
{
    unsigned int t[4];
    int r, c;
    for (r = 1; r < 4; r++)
    {
	for (c = 0; c < 4; c++)
	{
	    t[c] = state[r][(c + r) % 4];
	}
	for (c = 0; c < 4; c++)
	{
	    state[r][c] = t[c];
	}
    }
}

//ShiftRows inversion operation
void InvShiftRows(uint8_t state[][4])
{
    uint8_t t[4];
    int r, c;
    for (r = 1; r < 4; r++)
    {
	for (c = 0; c < 4; c++)
	{
	    t[c] = state[r][(c - r + 4) % 4];
	}
	for (c = 0; c < 4; c++)
	{
	    state[r][c] = t[c];
	}
    }
}

//White-Box-AES-Cryptogram process
/*
state  <-------   plaintext
for (r=1...9)
ShiftRow;
T-Box;
Tyi-Box;
Xor-Box
Type3Box
Xor-Box
ShiftRow;
T-Box;
state  ------>  ciphertext
*/
void WBAC_Encrypt_Block(uint8_t in[16], uint8_t out[16])
{
    int r, row, col, i, j;
    int k;
    unsigned int tyi_out[16];
    unsigned int type3_out[4];
    unsigned int xor_out1[4][3][8];
    unsigned int xor_out[4][3][8];

    //transform w32b to state
    w128b_2_State(in, state);

    for (r = 0; r < 10; r++)
    {
	if (r != 9)
	{
	    ShiftRows(state);

	    //T-box query
	    for (row = 0; row < 4; row++)
	    {
		for (col = 0; col < 4; col++)
		{
		    state[row][col] = T_Box0[r][row + col * 4][state[row][col]];
		}
	    }

	    //Tyi_box query
	    for (col = 0; col < 4; col++)
	    {
		for (row = 0; row < 4; row++)
		{
		    tyi_out[row + col * 4] = Tyi_Box0[row][state[row][col]];
		}
	    }

	    //Xor-box operation
	    /*
			 * col:  each column of state array,for Mixcolumn operation
			 * j:  for xor operation
			 * j=0:  ty0 xor ty1 <for round two : is ty4 xor ty5 ...>
			 * j=2:  ty2 xor ty3 <for round two : is ty6 xor ty7 ...>
			 * j=1:  for round one is : (ty0 xor ty1) xor (ty2 xor ty3)
			 * k:  for every 32-bit Tyibox query output , need 8 xor box
			*/
	    for (col = 0; col < 4; col++)
	    {
		for (j = 0; j < 3;)
		{
		    for (k = 0; k < 8; k++)
		    {
			xor_out[col][j][k] = Xor_Box0[(tyi_out[col * 4 + j] >> (28 - 4 * k)) & 0x0f][(tyi_out[col * 4 + j + 1] >> (28 - 4 * k)) & 0x0f];
			if (j == 2)
			{
			    xor_out[col][1][k] = Xor_Box0[xor_out[col][0][k]][xor_out[col][2][k]];
			}
		    }
		    j = j + 2;
		}

		//Type3 operation,a group of 8-bit, for the highest 8-bit, the positon=0
		for (row = 0; row < 4; row++)
		{
		    type3_out[row] = Type3out0[row][(xor_out[col][1][row * 2] << 4) ^ (xor_out[col][1][row * 2 + 1])];
		}

		//xor  operation for TyiBox query output
		for (j = 0; j < 3;)
		{
		    for (k = 0; k < 8; k++)
		    {
			xor_out1[col][j][k] = Xor_Box0[(type3_out[j] >> (28 - 4 * k)) & 0x0f][(type3_out[j + 1] >> (28 - 4 * k)) & 0x0f];
			if (j == 2)
			{
			    xor_out1[col][1][k] = Xor_Box0[xor_out1[col][0][k]][xor_out1[col][2][k]];
			}
		    }
		    j = j + 2;
		}
	    }
	    //just output merge
	    for (col = 0; col < 4; col++)
	    {
		for (row = 0; row < 4; row++)
		{
		    out[col * 4 + row] = (xor_out1[col][1][row * 2] << 4) ^ (xor_out1[col][1][row * 2 + 1]);
		}
	    }
	    //transform w128b to state
	    w128b_2_State(out, state);
	}
	//for last Round,the last Round no Mixcolumn operation,just Tbox query operation
	else
	{
	    w128b_2_State(out, state);
	    ShiftRows(state);
	    for (i = 0; i < 4; i++)
	    {
		for (j = 0; j < 4; j++)
		{
		    state[i][j] = T_Box0[9][i + j * 4][state[i][j]];
		}
	    }
	    for (int row = 0; row < 4; row++)
	    {
		for (int col = 0; col < 4; col++)
		{
		    out[row + col * 4] = state[row][col];
		}
	    }
	    w128b_2_State(out, state);
	}
    }
}

//White-Box-AES-Cryptogram process
void WBAC_Decrypt_Block(uint8_t in[16], uint8_t out[16])
{
    int r, row, col, i, j;
    int k;
    unsigned int Invxor_out[4][3][8];
    unsigned int Invxor_out1[4][3][8];
    unsigned int Invtype3_out[4];
    //transform w128b to state
    w128b_2_State(in, state);
    for (r = 9; r >= 0; r--)
    {
	if (r != 9)
	{
	    unsigned int Invtyi_out[16] = {0};
	    w128b_2_State(out, state);
	    //Tyi_box inversion operation
	    for (col = 0; col < 4; col++)
	    {
		for (row = 0; row < 4; row++)
		{
		    Invtyi_out[row + col * 4] = InvTyi_Box0[row][state[row][col]];
		}
	    }
	    //for each column of state array , Mixcolumn operation
	    for (col = 0; col < 4; col++)
	    {
		//Invxor InvTyiout
		for (j = 0; j < 3;)
		{
		    for (k = 0; k < 8; k++)
		    {
			Invxor_out[col][j][k] = InvXor_Box0[(Invtyi_out[col * 4 + j] >> (28 - 4 * k)) & 0x0f][(Invtyi_out[col * 4 + j + 1] >> (28 - 4 * k)) & 0x0f];
			if (j == 2)
			{
			    Invxor_out[col][1][k] = InvXor_Box0[Invxor_out[col][0][k]][Invxor_out[col][2][k]];
			}
		    }
		    j = j + 2;
		}
		//Type3
		for (row = 0; row < 4; row++)
		{
		    Invtype3_out[row] = Type3out0[row][(Invxor_out[col][1][row * 2] << 4) ^ (Invxor_out[col][1][row * 2 + 1])];
		}
		//Invxor  type3_out
		for (j = 0; j < 3;)
		{
		    for (k = 0; k < 8; k++)
		    {
			Invxor_out1[col][j][k] = InvXor_Box0[(Invtype3_out[j] >> (28 - 4 * k)) & 0x0f][(Invtype3_out[j + 1] >> (28 - 4 * k)) & 0x0f];
			if (j == 2)
			{
			    Invxor_out1[col][1][k] = InvXor_Box0[Invxor_out1[col][0][k]][Invxor_out1[col][2][k]];
			}
		    }
		    j = j + 2;
		}
	    }
	    //concatenate Type3out(Invxor_out1) to state
	    for (col = 0; col < 4; col++)
	    {
		for (row = 0; row < 4; row++)
		{
		    state[row][col] = (Invxor_out1[col][1][row * 2] << 4) ^ (Invxor_out1[col][1][row * 2 + 1]);
		}
	    }
	    //InvTBox
	    for (row = 0; row < 4; row++)
	    {
		for (col = 0; col < 4; col++)
		{
		    state[row][col] = InvT_Box0[r][row + col * 4][state[row][col]];
		}
	    }
	    InvShiftRows(state);
	    //transform state to out
	    for (i = 0; i < 4; i++)
	    {
		for (j = 0; j < 4; j++)
		{
		    out[i + j * 4] = state[i][j];
		}
	    }
	}
	else
	{
	    //InvTbox
	    for (row = 0; row < 4; row++)
	    {
		for (col = 0; col < 4; col++)
		{
		    state[row][col] = InvT_Box0[r][row + col * 4][state[row][col]];
		}
	    }
	    InvShiftRows(state);
	    //transform state to out
	    for (row = 0; row < 4; row++)
	    {
		for (col = 0; col < 4; col++)
		{
		    out[row + col * 4] = state[row][col];
		}
	    }
	}
    }
}

//pkcs7 padding in AES is pkcs5 padding
//@para:
//databuf:
//padbuf:
//datalen:
//return : the length of data after padding

void pkcs7_encode(uint8_t *databuf, uint8_t *padbuf, int datalen)
{

    int length = datalen + 16 - datalen % 16;

    //array for padding
    uint8_t padchr[16] = {0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};

    for (int i = 0; i < length; i++)
    {
	if (i < datalen)
	    padbuf[i] = databuf[i];
	else
	    padbuf[i] = padchr[datalen % 16];
    }
}

void pkcs7_decode(uint8_t *databuf, uint8_t *depadbuf, int datalen)
{
    for (int i = 0; i < datalen - databuf[datalen - 1]; i++)
	depadbuf[i] = databuf[i];
}

void dataBlockInit(wbacDataBlock **dataptr, uint8_t *arr, int length)
{
    *dataptr = (wbacDataBlock *)malloc(sizeof(wbacDataBlock));
    (*dataptr)->length = length;
    (*dataptr)->data = (uint8_t *)malloc(sizeof(uint8_t) * length);
    memcpy((*dataptr)->data, arr, length);
}

void dataBlockDestory(wbacDataBlock *dataptr)
{
    free(dataptr->data);
    dataptr->data = NULL;
    free(dataptr);
}

wbacDataBlock *wbac_cbc_encrypt(wbacDataBlock *input, uint8_t *iv)
{
    uint8_t iv_copy[16] = {0};
    memcpy(iv_copy, iv, 16);

    uint8_t buffer[16];
    int block = input->length / 16;
    wbacDataBlock *output = (wbacDataBlock *)malloc(sizeof(wbacDataBlock));
    output->length = 16 * block + 16;
    output->data = (uint8_t *)malloc(sizeof(uint8_t) * output->length);

    if (block > 0)
    {
	for (int i = 0; i < block; i++)
	{
	    memcpy(buffer, input->data + i * 16, 16);
	    for (int j = 0; j < 16; j++)
		buffer[j] = buffer[j] ^ iv[j];
	    WBAC_Encrypt_Block(buffer, buffer);
	    memcpy(output->data + i * 16, buffer, 16);
	    memcpy(iv, buffer, 16);
	}
    }
    memcpy(buffer, (input->data) + 16 * block, 16);
    pkcs7_encode(buffer, buffer, (input->length) - 16 * block);
    for (int j = 0; j < 16; j++)
	buffer[j] = buffer[j] ^ iv[j];
    WBAC_Encrypt_Block(buffer, buffer);
    memcpy(output->data + block * 16, buffer, 16);
    memcpy(iv, iv_copy, 16);

    return output;
}

wbacDataBlock *wbac_cbc_decrypt(wbacDataBlock *input, uint8_t *iv)
{

    uint8_t iv_copy[16] = {0};
    memcpy(iv_copy, iv, 16);

    uint8_t buffer[16];
    int block = input->length / 16;
    uint8_t *databuf = (uint8_t *)malloc(sizeof(uint8_t) * input->length);

    for (int r = 0; r < block; r++)
    {
	memcpy(buffer, input->data + 16 * r, 16);
	WBAC_Decrypt_Block(buffer, databuf + 16 * r);

	for (int i = 0; i < 16; i++)
	    (databuf + 16 * r)[i] ^= iv[i];

	//memcpy(iv, databuf + 16 * r, 16);
	memcpy(iv, buffer, 16);
    }
    wbacDataBlock *output = (wbacDataBlock *)malloc(sizeof(wbacDataBlock));
    output->length = input->length - databuf[input->length - 1];
    output->data = (uint8_t *)malloc(sizeof(uint8_t) * output->length);

    pkcs7_decode(databuf, output->data, input->length);
    memcpy(iv, iv_copy, 16);
    free(databuf);
    return output;
}
