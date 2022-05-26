#include "../include/vc_sw_crypt.h"
#include "../include/vc_sw_crypt_service.h"
#include "../include/vc_key.h"


#define MAX_BUF_LEN (MAX_RSA_BITS / 8 * 2 + 10)

s32 checkOutBufferLen(u32 inLen, u32 outLen)
{
    u32 mod = inLen % 16;
    u32 need;
    if (mod)
        need = inLen + (16 - mod);
    else
        need = inLen;

    if (outLen < need)
        return -1;

    return (inLen == outLen) ? 0 : 1;
}

void CalcX2(vc_input_info* inputkey, u8* outbuf)
{
    s32 i;
    u8 flag = 0;
    u16 tmp = 0;

    for (i = inputkey->dataSize - 1; i>= 0; i--)
    {
        tmp = inputkey->data[i] << 1;
        outbuf[i] = (tmp & 0xff) + flag;
        flag = ((tmp & 0xff00 ) != 0);
    }
}

s32 CMAC_AesEnc(vc_input_info* data, vc_input_info* key, u8* iv, vc_output_info* outBuf)
{
    s32 res = 0;

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    res = mbedtls_aes_setkey_enc(&ctx, key->data, (key->dataSize)*8);
    if (res != 0)
    {
        mbedtls_aes_free(&ctx);
        return res;
    }

    res = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data->dataSize, iv, data->data, outBuf->data);
    if (res != 0)
    {
        mbedtls_aes_free(&ctx);
        return res;
    }
    outBuf->dataSize = data->dataSize;

    mbedtls_aes_free(&ctx);
    return 0;
}


s32 CalcK1K2(vc_input_info* inputkey, u8* k1, u8* k2)
{
    s32 res = 0;

    u8 iv[16] = {0};
    u8 out[16] = {0};

    vc_input_info input;
    input.data = iv;
    input.dataSize = 16;

    vc_output_info outBuf;
    outBuf.data = out;
    outBuf.dataSize = 16;

    res = CMAC_AesEnc(&input, inputkey, iv, &outBuf);   // CIPH(L)
    if (res != 0)
    {
        return -1;
    }
    CalcX2((vc_input_info *)&outBuf, k1);             //k1
    if ( (outBuf.data[0] & 0x80) != 0)
    {
        k1[15] ^= 0x87;
    }

    vc_input_info tmp;
    tmp.data = k1;
    tmp.dataSize = 16;

    CalcX2(&tmp, k2);                //k2

    if ((k1[0] & 0x80) != 0)
    {
        k2[15] ^= 0x87;
    }

    return res;
}

s32 vc_check_auth(vc_authentic_info *authInfo)
{
    return 0;
}
/*****************************/

void padding(u8 *data , u32 *len, PADDING_MODE m)
{
    u32 tmp_len = *len;
    //if (*len %16)
        *len = ((*len/16)+1)*16;
    //else
    //    return ;


    s32 i;
    s32 pdlen = *len - tmp_len;

    for (i = tmp_len; i < *len ;i++)
    {
        u8 padding_char = 0;
        switch (m)
        {
            case ZERO_PADDING:
            {
                padding_char = 0;
            }
            break;

            case PKCS7_PADDING:
            {
                padding_char = pdlen;
        }
            break;

            default:
                return;
        }

        data[i] = padding_char;
    }
}

s32 vc_get_file_size(u8 * filepath)
{
    s32 s;

    FILE *fp;
    fp = fopen(filepath, "rb");
    if(fp == NULL)
    {
        VC_LOG_E("vc_get_file_size %s error\n", filepath);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    s = ftell(fp);

    fclose(fp);
    fp = NULL;

    return s;
}

s32 vc_hash_len(HASH_ALG type)
{
    s32 v = 0;

    switch (type)
    {
        case HASH_MD_SHA1:
        {
            v = 20*8;
        }
        break;

        case HASH_MD_SHA256:
        case HASH_MD_SHA224:
        case HASH_SM3:
        {
            v = 32;
        }
        break;

        case HASH_MD_SHA384:
        case HASH_MD_SHA512:
        {
            v = 64;
        }
        break;

        default:
            return -ERR_SWITH;
    }
    return v;
}

void vc_white_box_enc(vc_input_info *indata, vc_output_info *outdata)
{
    wbacDataBlock *plain = NULL;
    wbacDataBlock *cipher = NULL;
    u8 wbIV[16] = {0};

    dataBlockInit(&plain, indata->data, indata->dataSize);
    cipher = wbac_cbc_encrypt(plain, wbIV);

    memcpy(outdata->data, cipher->data, cipher->length);
    outdata->dataSize = cipher->length;

    dataBlockDestory(plain);
    dataBlockDestory(cipher);
}

void vc_white_box_decrypt(vc_input_info *indata, vc_output_info *outdata)
{
    unsigned char in_iv[16] = {0};

    wbacDataBlock* cipher = NULL;
    dataBlockInit(&cipher, indata->data, indata->dataSize);

    wbacDataBlock *res = NULL;
    res = wbac_cbc_decrypt(cipher, in_iv);

    outdata->dataSize = res->length;
    memcpy(outdata->data, res->data, res->length);

    dataBlockDestory(cipher);
    dataBlockDestory(res);
}

s32 vc_kdf(HASH_ALG type ,vc_input_info *zInfo, u32 klen, vc_output_info *kInfo)
{
    s32 res = 0;

    vc_hash_st hashInfo;
    hashInfo.hash_type = type;

    s32 v = 0;
    v = vc_hash_len(type)*8;
    if (v == 0)
        return -ERR_PARAM;

    u32 ct = 0x00000001;
    s32 round = klen/v;
    s32 haflag = klen % v == 0 ? 0 : 1;
    s32 i, offset;
    offset = 0;
    vc_output_info tmpout;
    u8 tmpbuf[64] = {0};
    tmpout.data = tmpbuf;
    tmpout.dataSize = 64;
    for (i = 1 ; i <= round + haflag; i++ )
    {
        zInfo->data[zInfo->dataSize] = (ct & 0xff000000) >> 6;
        zInfo->data[zInfo->dataSize+1] = ct & 0x00ff0000 >> 4;
        zInfo->data[zInfo->dataSize+2] = ct & 0x0000ff00 >> 2;
        zInfo->data[zInfo->dataSize+3] = ct & 0x000000ff;     // z||ct
        zInfo->dataSize += 4;

        res = vc_hash(&hashInfo, zInfo, &tmpout);
        if (res != 0)
            return res;

        memcpy(&kInfo->data[offset], tmpout.data, tmpout.dataSize);
        offset += tmpout.dataSize;

        ct ++;
    }
    kInfo->dataSize = klen/8;

    return res;
}

void vc_or_data(vc_input_info *in, vc_output_info *out)
{
    s32 i;
    for (i = 0; i < in->dataSize; i++)
    {
        out->data[i] ^= in->data[i];
    }
}

void vc_or_data_add(vc_input_info *in, vc_output_info *out)
{
    s32 i;
    for (i = 0; i < in->dataSize; i++)
    {
        out->data[i] = (out->data[i] ^ in->data[i]) + (0x75*i)%0x25;  //magic num
    }
}

void vc_sub_data_or(vc_input_info *in, vc_output_info *out)
{
    s32 i;
    s32 range = 0;
    range = in->dataSize < out->dataSize ? in->dataSize : out->dataSize;

    for (i = 0; i < range; i++)
    {
        out->data[i] =  (in->data[i] - (0x75*i)%0x25) ^ out->data[i];
    }
}


#if 0
s32 vc_whitebox_with_data(vc_input_info *input, void *output ,int mod)
{
    s32 res = 0;
    u32 offset = 0;
    vc_input_info tmp;
    s32 endflag = 0;
    u8 * filepath;
    FILE* fout = NULL;
    u8 writebuf[READ_MAX + 16];
    vc_output_info *pout;

    if (input == NULL || output == NULL)
        return -ERR_PARAM;

    if (mod == 0)
    {
        filepath = (u8 *)output;
        fout  = fopen(filepath, "wb");
        if (fout == NULL)
        {
            VC_LOG_E("vc_whitebox_with_data open error\n");
            return -ERR_PARAM;
        }
    }

    tmp.data = &input->data[offset];

    if (input->dataSize < READ_MAX)
    {
        tmp.dataSize = input->dataSize;
        endflag = 1;
    }
    else
    {
        tmp.dataSize = READ_MAX;
    }

    vc_output_info tmpout;
    tmpout.data = writebuf;
    if (mod == 1)
    {
        pout = (vc_output_info *)output;
        memset(pout->data, 0, pout->dataSize);
        pout->dataSize = 0;

    }
    while (offset < input->dataSize)
    {
        if (mod == 0)
        {
            vc_white_box_enc(&tmp, &tmpout);
            fwrite(tmpout.data, 1, tmpout.dataSize, fout);
        }
        else
        {
            if (endflag != 1)
                tmp.dataSize += 16;
            vc_white_box_decrypt(&tmp, &tmpout);
            memcpy(&(pout->data[pout->dataSize]), tmpout.data, tmpout.dataSize);
            pout->dataSize += tmpout.dataSize;
        }

        offset += tmp.dataSize;
        tmp.data = &input->data[offset];

        if (input->dataSize - offset < READ_MAX)
        {
            tmp.dataSize = input->dataSize - offset;
            endflag = 1;
        }
        else
        {
            tmp.dataSize = READ_MAX;
        }
    }

    if (mod == 1)
    {
        pout->data[pout->dataSize] = 0;
        pout->dataSize ++;
    }

exit:
    if (fout != NULL)
    {
        fclose(fout);
        fout = NULL;
    }
    return res;
}


s32 vc_whitebox_with_file(u8 *infile, void *output, int mod)
{
    s32 res = 0;
    FILE *fin = NULL;
    FILE *fout = NULL;
    u8 indatabuff[READ_MAX + 16] = {0};
    u8 *filepath;
    u8 writebuf[READ_MAX + 16] = {0};
    vc_output_info *pout;

    vc_input_info indata;
    indata.data = indatabuff;
    indata.dataSize = sizeof(indatabuff);

    fin  = fopen(infile, "rb");
    if (fin == NULL)
    {
        VC_LOG_E("write key in file error %s\n ", infile);
        res = -ERR_PARAM;
        goto exit;
    }

    if (mod == 0)
    {
        filepath = (u8 *)output;
        fout  = fopen(filepath, "wb");
        if (fout == NULL)
        {
            VC_LOG_E("vc_whitebox_with_file open error\n");
            return -ERR_PARAM;
        }
    }

    vc_output_info tmpout;
    tmpout.data = writebuf;

    if (mod == 1)
    {
        pout = (vc_output_info *)output;
        memset(pout->data, 0, pout->dataSize);
        pout->dataSize = 0;

    }

    while(1)
    {
        if (mod == 0)
        {
            indata.dataSize = fread(indata.data, 1, READ_MAX, fin);
            if (indata.dataSize == 0)
                break;
            vc_white_box_enc(&indata, &tmpout);
            fwrite(tmpout.data, tmpout.dataSize, 1 ,fout);
        }
        else
        {
            indata.dataSize = fread(indata.data, 1, READ_MAX + 16, fin);
            if (indata.dataSize == 0)
                break;
            vc_white_box_decrypt(&indata, &tmpout);
            memcpy(&(pout->data[pout->dataSize]), tmpout.data, tmpout.dataSize);
            pout->dataSize += tmpout.dataSize;
        }
    }

    if (mod == 1)
    {
        pout->data[pout->dataSize] = 0;
        pout->dataSize ++;
    }

exit:
    if (fin != NULL)
    {
        fclose(fin);
        fin = NULL;
    }
    if (fout != NULL)
    {
        fclose(fout);
        fout = NULL;
    }


    return res;
}
#endif

void unpading(PADDING_MODE mod, vc_output_info * outdata)
{
    u8 j;
    switch (mod)
    {
        case PKCS7_PADDING:
        {
        	u8 padding_char = outdata->data[outdata->dataSize -1];
            for (j = 0; j < padding_char; j++)
            {
                outdata->dataSize --;
            }
        }
        break;

        default:
            break;
    }

  //  outdata->dataSize = i;
}



