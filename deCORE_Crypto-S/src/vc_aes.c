#include "../include/vc_aes.h"
#include "../include/vc_key.h"

s32 vc_get_aes_key(u32 keyid, vc_output_info* keyInfo)
{
    s32 res = 0;

    FILE *fp = NULL;
    u8 tmpStr[128] = {0};
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

    if (keyType != KEY_TYPE_AES)
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    vc_input_info outKey;
    outKey.data = tmpStr;
    outKey.dataSize = sizeof(tmpStr);
    memset(tmpStr, 0, sizeof(tmpStr));
    res = vc_get_key_data(fp, (vc_output_info*)&outKey);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    vc_white_box_decrypt(&outKey, keyInfo);

exit:
    fclose(fp);

    return res;
}

s32 vc_get_tmp_aes_key(u8 keyid, vc_output_info* keyInfo)
{
    s32 res = 0;

    vc_key_type keyType;

    res = vc_check_tmp_keymac(keyid, NULL);

    keyType = vc_get_tmp_key_type(keyid);

    if (keyType != KEY_TYPE_AES)
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    memset(keyInfo->data, 0, keyInfo->dataSize);
    res = vc_get_tmp_key_data(keyid, (vc_output_info*)keyInfo);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

exit:
    return res;
}


s32 do_aes_crypt(vc_aes_encdec_info* aesEncDecInfo, vc_output_info *keyInfo, vc_input_info* inputInfo, vc_output_info* outputInfo, s32 enc_mod)
{
    s32 res = 0;

    if (enc_mod == OPT_ENC  &&
        (aesEncDecInfo->aes_enc_mode == AES_ENC_CBC || aesEncDecInfo->aes_enc_mode == AES_ENC_ECB) &&
        aesEncDecInfo->aes_padding_mode != NO_PADDING)
    {
        padding(inputInfo->data, &(inputInfo->dataSize), aesEncDecInfo->aes_padding_mode);
    }

    switch (aesEncDecInfo->aes_enc_mode)
    {
       case (AES_ENC_ECB):
       {
            if (inputInfo->dataSize != 16 || outputInfo->dataSize < 16)
            {
                VC_LOG_E("aes ecb must use 16 bytes data\n");
                return -ERR_PARAM;
            }

            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            if (enc_mod == OPT_ENC)
                res = mbedtls_aes_setkey_enc(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
            else
                res = mbedtls_aes_setkey_dec(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
            if (res != 0)
            {
                mbedtls_aes_free(&ctx);
                return res;
            }

            res = mbedtls_aes_crypt_ecb(&ctx, enc_mod, inputInfo->data, outputInfo->data);
            if (res != 0)
            {
                mbedtls_aes_free(&ctx);
                return res;
            }
            outputInfo->dataSize = inputInfo->dataSize;
            mbedtls_aes_free(&ctx);
        }
        break;

        case (AES_ENC_CBC):
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            if (enc_mod == OPT_ENC)
               res = mbedtls_aes_setkey_enc(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
            else
               res = mbedtls_aes_setkey_dec(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
           if (res != 0)
           {
               mbedtls_aes_free(&ctx);
               return res;
           }

           if (aesEncDecInfo->iv == NULL)
           {
               mbedtls_aes_free(&ctx);
               return -ERR_PARAM;
           }

           res = mbedtls_aes_crypt_cbc(&ctx, enc_mod, inputInfo->dataSize, aesEncDecInfo->iv, inputInfo->data, outputInfo->data);
           if (res != 0)
           {
               mbedtls_aes_free(&ctx);
               return res;
           }
           outputInfo->dataSize = inputInfo->dataSize;
           mbedtls_aes_free(&ctx);
       }
       break;

       case (AES_ENC_GCM):
       {
           mbedtls_gcm_context ctx;
           mbedtls_gcm_init( &ctx );
           mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, keyInfo->data, (keyInfo->dataSize)*8 );
           if (res != 0)
           {
               mbedtls_gcm_free(&ctx);
               return res;
           }

           res = mbedtls_gcm_crypt_and_tag( &ctx, enc_mod,
                                    inputInfo->dataSize,
                                    aesEncDecInfo->iv, 16,
                                    aesEncDecInfo->addData, aesEncDecInfo->addLen,
                                    inputInfo->data, outputInfo->data, 16, aesEncDecInfo->tagBuf );

           if (res != 0)
           {
               VC_LOG_E("vc_aes_crypt AES_ENC_GCM mbedtls_gcm_crypt_and_tag error %d\n", res);
               mbedtls_gcm_free(&ctx);
               return res;
           }
           outputInfo->dataSize = inputInfo->dataSize;

           if (enc_mod == OPT_DEC)
           {
               s32 i;
               for (i = 0; i < 16; i++)
               {
                   if (aesEncDecInfo->tagBuf[i] != aesEncDecInfo->tagVerify[i])
                   {
                       VC_LOG_E("aes gcm decrypt success ,but the mac may be wrong\n");
                       res = -ERR_MAC;
                       break;
                   }
               }
           }
           mbedtls_gcm_free(&ctx);
       }
       break;

       case (AES_ENC_OFB):
       {
           mbedtls_aes_context ctx;
           mbedtls_aes_init( &ctx );
           size_t offset = 0;

           mbedtls_aes_setkey_enc(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
           if (res != 0)
           {
               mbedtls_aes_free(&ctx);
               return res;
           }

           if (aesEncDecInfo->iv == NULL)
           {
               mbedtls_aes_free(&ctx);
               return -ERR_PARAM;
           }
           res = mbedtls_aes_crypt_ofb(&ctx, inputInfo->dataSize, &offset, aesEncDecInfo->iv, inputInfo->data, outputInfo->data);
           if (res != 0)
           {
               VC_LOG_E("vc_aes_crypt AES_ENC_OFB mbedtls_aes_crypt_ofb error %d\n", res);
               mbedtls_aes_free(&ctx);
               return res;
           }
           outputInfo->dataSize = inputInfo->dataSize;
           mbedtls_aes_free(&ctx);
       }
       break;

       case (AES_ENC_CFB):
       {
           if (keyInfo->dataSize != 16)
           {
               VC_LOG_E("aes cfb key must be 128 bits \n");
               return -ERR_KEYLEN;
           }

           mbedtls_aes_context ctx;
           mbedtls_aes_init( &ctx );
           size_t offset = 0;

           mbedtls_aes_setkey_enc(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
           if (res != 0)
           {
               mbedtls_aes_free(&ctx);
               return res;
           }

           if (aesEncDecInfo->iv == NULL)
           {
               mbedtls_aes_free(&ctx);
               return -ERR_PARAM;
           }
           res = mbedtls_aes_crypt_cfb128( &ctx, enc_mod, inputInfo->dataSize, &offset, aesEncDecInfo->iv, inputInfo->data, outputInfo->data);
           if (res != 0)
           {
               VC_LOG_E("vc_aes_crypt AES_ENC_CFB mbedtls_aes_crypt_cfb128 error %d\n", res);
               mbedtls_aes_free(&ctx);
               return res;
           }
           outputInfo->dataSize = inputInfo->dataSize;
           mbedtls_aes_free(&ctx);
       }
       break;

       case (AES_ENC_CTR):
       {
          /* if (keyInfo.dataSize != 16)
           {
               VC_LOG_E("aes ctr key must be 128 bits \n");
               return -ERR_KEYLEN;
           }*/

           mbedtls_aes_context ctx;
           mbedtls_aes_init( &ctx );
           size_t offset = 0;

           mbedtls_aes_setkey_enc(&ctx, keyInfo->data, (keyInfo->dataSize)*8);
           if (res != 0)
           {
               mbedtls_aes_free(&ctx);
               return res;
           }

           if (aesEncDecInfo->iv == NULL)
           {
               mbedtls_aes_free(&ctx);
               return -ERR_PARAM;
           }
           u8 stream_block[16];
           res = mbedtls_aes_crypt_ctr(&ctx, inputInfo->dataSize, &offset, aesEncDecInfo->iv, stream_block, inputInfo->data, outputInfo->data);
           if (res != 0)
           {
               VC_LOG_E("vc_aes_crypt AES_ENC_CTR mbedtls_aes_crypt_ctr error %d\n", res);
               mbedtls_aes_free(&ctx);
               return res;
           }
           outputInfo->dataSize = inputInfo->dataSize;
           mbedtls_aes_free(&ctx);

       }
       break;

       default:
           return -ERR_SWITH; //算法选择错误
    }

    if (enc_mod == OPT_DEC  &&
        (aesEncDecInfo->aes_enc_mode == AES_ENC_CBC || aesEncDecInfo->aes_enc_mode == AES_ENC_ECB) &&
        aesEncDecInfo->aes_padding_mode != NO_PADDING)
    {
        unpading(aesEncDecInfo->aes_padding_mode, outputInfo);
    }

    return res ;
}

s32 vc_aes_crypt(vc_aes_encdec_info* aesEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo, s32 enc_mod)
{
    s32 res = 0;
    vc_output_info key;
    vc_gen_key_info *keyInfo;
    u8 keydata[48] = {0};

    if (aesEncDecInfo == NULL || inputInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }
    keyInfo = &aesEncDecInfo->keyInfo;

    res = checkOutBufferLen(inputInfo->dataSize, outputInfo->dataSize);
    if ((inputInfo->dataSize > outputInfo->dataSize) || res < 0)
    //if (inputInfo->dataSize > outputInfo->dataSize)
    {
        return -ERR_NOT_ENOUGH; // 长度不够
    }

    key.data = keydata;
    key.dataSize = sizeof(keydata);
    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_aes_key(keyInfo->keyID, &key);
    else
        res = vc_get_tmp_aes_key(keyInfo->keyID, &key);
    if (res < 0)
    {
        return res;  //获取key失败
    }
    if ((key.dataSize != 16) && (key.dataSize != 24) && (key.dataSize != 32))
    {
        VC_LOG_E("key len %d is not support \n", key.dataSize);
        return -ERR_KEYLEN;
    }

    res = do_aes_crypt(aesEncDecInfo, &key, inputInfo, outputInfo, enc_mod);
    if (res != 0)
    {
        VC_LOG_E("do_aes_crypt error %d \n", res);
    }

    return res;
}

