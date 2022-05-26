#include "../include/vc_mac.h"
#include "../include/vc_key.h"

s32 vc_get_hmac_key(u32 keyid, vc_output_info* keyInfo, s32 ishmac)
{
    s32 res = 0;

    FILE *fp;
    u8 tmpStr[128];
    vc_key_type keyType;

    res = vc_set_keybit();
    if (res != 0)
    {
        VC_LOG_E("open dir error %d\n", res);
        return -ERR_PARAM;
    }

    sprintf(tmpStr, "%s/KEY_%d", KEY_FILE_PATH, keyid);
    fp = fopen(tmpStr, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("vc_get_aes_key open file error\n");
        return -ERR_PARAM; //打开文件失败
    }

    res = vc_check_keymac(fp, NULL);

    keyType = vc_get_key_type(fp);

    if (!(keyType == KEY_TYPE_HMAC && ishmac == 1)
        && !(keyType == KEY_TYPE_CMAC && ishmac == 0))
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    vc_output_info outKey;
    outKey.data = tmpStr;
    outKey.dataSize = sizeof(tmpStr);
    memset(tmpStr, 0, sizeof(tmpStr));
    res = vc_get_key_data(fp, &outKey);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    vc_white_box_decrypt((vc_input_info*)&outKey, keyInfo);

exit:
    fclose(fp);

    return res;
}


s32 do_CalcCmac(vc_input_info     *input,  vc_cmac_info *mackey, vc_output_info *cmac)
{
    s32 res = 0;

    s32 block = 0;
    s32 i;
    u8 k1[16] = {0};
    u8 k2[16] = {0};
    u8 *tmpout = NULL;
    u32 tmplen = 0;
    u8 c[16] = {0};
    u8 keydata[64] = {0};
    vc_input_info tmpMsg;
    vc_input_info cmacKey;
    vc_gen_key_info *keyInfo;

    if (input == NULL || mackey == NULL || cmac == NULL)
    {
        return -ERR_PARAM;
    }

    keyInfo = &mackey->keyInfo;

    cmacKey.data = keydata;
    res = vc_get_hmac_key(keyInfo->keyID, (vc_output_info *)&cmacKey, 0);
    if (res < 0)
    {
        return -ERR_KEY_READ;  //获取key失败
    }

    res = CalcK1K2(&cmacKey, k1,k2);
    if (res != 0)
    {
        VC_LOG_E("calck1k2 error %d\n",res);
        return res;
    }

    if (input->dataSize == 0)
        block = 1;
    else
        block = (input->dataSize / 16) + ((input->dataSize % 16) != 0);


    tmplen = block * 16;
    tmpout = (u8 *)malloc(tmplen);
    if (tmpout == NULL)
    {
        VC_LOG_E("malloc error\n");
        return -ERR_MALLOC;
    }
    memset(tmpout, 0, tmplen);
    memcpy(tmpout, input->data, input->dataSize);

    if ((input->dataSize % 16) || (input->dataSize == 0))          //Mn
    {
    	tmpout[input->dataSize] = 0x80;

        for (i = 0; i < 16; i++)
        {
            tmpout[(block - 1) * 16 + i] ^= k2[i];
        }
    }
    else
    {
        for (i = 0; i < 16; i++)
        {
            tmpout[(block - 1) * 16 + i] ^= k1[i];
        }
    }

    for (i = 1; i <= block ;i++)
    {

        tmpMsg.data = &(tmpout[(i - 1) * 16]);
        tmpMsg.dataSize = 16;

        res = CMAC_AesEnc(&tmpMsg, &cmacKey, c, cmac);
        if (res != 0)
        {
            VC_LOG_E("aesenc is error %d\n", res);
            goto exit;
        }
    }

exit:
    if (tmpout != NULL)
        free(tmpout);
    tmpout = NULL;

    return res;
}

s32 do_VerifyCmac(vc_input_info     *input,  vc_cmac_st *mackey, vc_output_info *cmac)
{
	s32 res = 0;

	vc_output_info tmpcmac;
	u8 buffer[16];
	tmpcmac.data = buffer;
    vc_input_info keyInfo;

	if (input == NULL || mackey == NULL || cmac == NULL)
	{
		return -ERR_PARAM;
	}

	res = vc_CalcCmac(input, mackey, &tmpcmac);
	if (res != 0)
	{
		VC_LOG_E("calc cmac error\n");
		return res;
	}

	s32 i;
	for (i = 0; i < 16 ;i++)
	{
		if (tmpcmac.data[i] != cmac->data[i])
		{
			VC_LOG_E("vc_VerifyCmac failed \n");
			return -ERR_MAC;
		}
	}

	return res;
}

s32 do_CalcHmac(vc_hmac_info *hmac_info, vc_input_info *input, vc_output_info *hmac)
{
    s32 res = 0;
    vc_output_info key;
    u8 keydata[48] = {0};
    vc_gen_key_info *keyInfo;

    if (hmac_info == NULL || input == NULL || hmac == NULL)
    {
        return -ERR_PARAM;
    }

    keyInfo = &hmac_info->keyInfo;

    key.data = keydata;
    res = vc_get_hmac_key(keyInfo->keyID, &key, 1);
    if (res < 0)
    {
        return res;  //获取key失败
    }

    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);

    res = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(hmac_info->hash_type), 1);
    if (res != 0) {
        VC_LOG_E("vc_CalcHmac mbedtls_md_setup() return %d\n", res);
        mbedtls_md_free(&sha_ctx);
        return res;
    }

    res = mbedtls_md_hmac_starts(&sha_ctx, key.data, key.dataSize);/////////////
    if (res != 0)
        goto exit;
    mbedtls_md_hmac_update(&sha_ctx, input->data, input->dataSize);//////////
    if (res != 0)
        goto exit;
    mbedtls_md_hmac_finish(&sha_ctx, hmac->data);
    if (res != 0)
        goto exit;
exit:
    mbedtls_md_free(&sha_ctx);

    return res;
}

