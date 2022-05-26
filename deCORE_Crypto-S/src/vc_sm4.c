#ifdef SMENABLE
#include "../include/vc_sm4.h"
#include "../include/vc_sw_crypt.h"
#include "../include/openssl/sms4.h"
#include "../include/vc_key.h"

s32 vc_get_sm4_key(u32 keyid, vc_output_info* keyInfo)
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

    if (keyType != KEY_TYPE_SM4)
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

s32 vc_get_tmp_sm4_key(u8 keyid, vc_output_info* keyInfo)
{
    s32 res = 0;
    u8 tmpStr[128] = {0};

    vc_key_type keyType;

    res = vc_check_tmp_keymac(keyid, NULL);

    keyType = vc_get_tmp_key_type(keyid);

    if (keyType != KEY_TYPE_SM4)
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


s32 do_sm4_crypt(vc_sm4_encdec_info* sm4EncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo, s32 enc_mod)
{
    s32 res = 0;

    vc_output_info key;
    vc_gen_key_info *keyInfo;
    u8 keydata[16] = {0};
    sms4_key_t sm4key;

    if (sm4EncDecInfo == NULL || inputInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }
    keyInfo = &sm4EncDecInfo->keyInfo;

    res = checkOutBufferLen(inputInfo->dataSize, outputInfo->dataSize);
    if ((inputInfo->dataSize > outputInfo->dataSize) || res < 0)
    //if (inputInfo->dataSize > outputInfo->dataSize)
    {
        return -ERR_NOT_ENOUGH; // 长度不够
    }

    if (enc_mod == OPT_ENC && (sm4EncDecInfo->sm4_enc_mode == SM4_ENC_CBC || sm4EncDecInfo->sm4_enc_mode == SM4_ENC_ECB) &&
        (sm4EncDecInfo->padding_mode != NO_PADDING))
    {
        padding(inputInfo->data, &(inputInfo->dataSize), sm4EncDecInfo->padding_mode);
    }

    key.data = keydata;
    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_sm4_key(keyInfo->keyID, &key);
    else
        res = vc_get_tmp_sm4_key(keyInfo->keyID, &key);
    if (res < 0)
    {
        VC_LOG_E("do_sm4_crypt , vc_get_aes_key %d\n", res);
        return -ERR_KEY_READ;  //获取key失败
    }
    if ((key.dataSize != 16))
    {
        VC_LOG_E("key len %d is not support \n", key.dataSize);
        return -ERR_KEYLEN;
    }

    switch (sm4EncDecInfo->sm4_enc_mode)
    {
        case (SM4_ENC_CBC):
        {
            if (enc_mod == OPT_ENC)
                sms4_set_encrypt_key(&sm4key, key.data);
            else
                sms4_set_decrypt_key(&sm4key, key.data);
            sms4_cbc_encrypt(inputInfo->data, outputInfo->data, inputInfo->dataSize, &sm4key, sm4EncDecInfo->iv ,enc_mod);
            outputInfo->dataSize = inputInfo->dataSize;
        }
        break;

        case (SM4_ENC_ECB):
        {
            if (enc_mod == OPT_ENC)
                sms4_set_encrypt_key(&sm4key, key.data);
            else
                sms4_set_decrypt_key(&sm4key, key.data);
            sms4_ecb_encrypt(inputInfo->data, outputInfo->data, &sm4key, enc_mod);
            outputInfo->dataSize = inputInfo->dataSize;
        }
        break;

        case (SM4_ENC_CFB):
        {
            sms4_set_encrypt_key(&sm4key, key.data);
            s32 block = ((inputInfo->dataSize % 16) == 0 ? 0 : 1);
            sms4_cfb128_encrypt(inputInfo->data, outputInfo->data, inputInfo->dataSize, &sm4key, sm4EncDecInfo->iv , &block, enc_mod);
            outputInfo->dataSize = inputInfo->dataSize;
        }
        break;

        case (SM4_ENC_OFB):
        {
            sms4_set_encrypt_key(&sm4key, key.data);
            s32 block = ((inputInfo->dataSize % 16) == 0 ? 0 : 1);
            sms4_ofb128_encrypt(inputInfo->data, outputInfo->data, inputInfo->dataSize, &sm4key, sm4EncDecInfo->iv, &block);
            outputInfo->dataSize = inputInfo->dataSize;
        }
        break;

        case (SM4_ENC_CTR):
        {
            sms4_set_encrypt_key(&sm4key, key.data);
            s32 block = ((inputInfo->dataSize % 16) == 0 ? 0 : 1);
            u8 stream_block[16];
            sms4_ctr128_encrypt(inputInfo->data, outputInfo->data, inputInfo->dataSize, &sm4key, sm4EncDecInfo->iv, stream_block, &block);
            outputInfo->dataSize = inputInfo->dataSize;
        }
        break;

        default:
            return -ERR_SWITH; //算法选择错误
    }

    if (enc_mod == OPT_DEC && (sm4EncDecInfo->sm4_enc_mode == SM4_ENC_CBC || sm4EncDecInfo->sm4_enc_mode == SM4_ENC_ECB) &&
        (sm4EncDecInfo->padding_mode != NO_PADDING))
    {
        unpading(sm4EncDecInfo->padding_mode, outputInfo);
    }

    return res;
}

#endif

