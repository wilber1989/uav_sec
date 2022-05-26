#include "../include/vc_key.h"
#include "../include/vc_rsa.h"
#include "../include/vc_sm2.h"
#include "../include/vc_aes.h"
#include "../include/vc_ecc.h"

#include<dirent.h>
#include<sys/types.h>

typedef struct
{
    u8 flag;
    u8 type;
    u8 *keyMac;
    u8 *keydata;
    u32 keylen;
}vc_tmp_key;

static u64 keybit[2] = {0};
static vc_tmp_key tmp_key[NUM_TMP_KEY] = {0};


const u8 KEY_TYPE_STR[] = "type = ";

s32 vc_get_key_type(FILE *fp)
{
    s32 keyType = -1;
    u8 tmpstr[32] = {0};
    u8 *tmp;

    tmp = fgets(tmpstr, sizeof(tmpstr), fp);
    if (tmp == NULL)
        return -ERR_KEYFILE_BROKEN;

    if ((tmp = strstr(tmpstr, KEY_TYPE_STR)) == NULL)
    {
        VC_LOG_E("key file error\n");
        return -ERR_KEYFILE_BROKEN;  //key 文件损坏
    }
    keyType = atoi(tmp + strlen(KEY_TYPE_STR));

    return keyType;
}

s32 vc_get_tmp_key_type(u8 keyid)
{
    s32 keyType = -1;
    u8 tmpid = keyid - 1 - MAX_KEY_ID;
    keyType = tmp_key[tmpid].type & 0xff;

    return keyType;
}

s32 vc_get_key_data(FILE *fp, vc_output_info *outdata)
{
    s32 res = 0;

    res = fread(outdata->data,1,outdata->dataSize, fp);
    if (res > 0)
        outdata->dataSize = res;

    if (res >= 0)
        res = 0;

    return res;
}

s32 vc_get_tmp_key_data(u8 keyid, vc_output_info *outdata)
{
    s32 res = 0;

    u8 tmpid = keyid - 1 - MAX_KEY_ID;
    memcpy(outdata->data, tmp_key[tmpid].keydata, tmp_key[tmpid].keylen);
    outdata->dataSize = tmp_key[tmpid].keylen;

    return res;
}

s32 vc_set_keybit()
{
    s32 res = 0;

    DIR *dir;
    struct dirent *ptr = NULL;

    if ((dir = opendir(KEY_FILE_PATH)) == NULL)
    {
        VC_LOG_E("vc_set_keybit can not open dir %s\n", KEY_FILE_PATH);
        return -ERR_PARAM; // open dir error
    }

    memset(keybit, 0 ,sizeof(keybit));

    while((ptr = readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)
            continue;
        else if ((ptr->d_type == 8) && (strstr(ptr->d_name, KEY_FILE_NAME) != NULL))  //8 == FILE
        {
            s8 *tmp;
            s32 keyid;
            tmp = ptr->d_name + 4;
            keyid = atoi(tmp);
            if (keyid <= 0 || keyid > MAX_KEY_ID)
                continue;
            if (keyid < 64)
                keybit[0] |= ((u64)1<<keyid);
            else
                keybit[1] |= ((u64)1<<(keyid - 64));
        }

    }
    res = closedir(dir);

    return res;
}

s32 vc_return_tmp_keyid()
{
    s32 res = -1;

    s32 i;
    for (i = 0; i < NUM_TMP_KEY; i++)
    {
        if (tmp_key[i].flag == 0 &&
            tmp_key[i].keyMac == NULL &&
            tmp_key[i].keydata == NULL)
            return i + 1 + MAX_KEY_ID;
    }

    return res;
}

s32 vc_return_file_keyid()
{
    s32 keyid = -1;

    if (keybit[0] == 0xfffffffffffffffe && keybit[1] == 0xFFFFFFFFF)
    {
        VC_LOG_E("too many key\n");
        return -1;
    }

    s32 i;
    u64 tmp = 0;
    for (i = 1; i < 64; i++)
    {
        tmp = keybit[0] & ((u64)1<<i);
        if (tmp == 0)
            return i;
    }

    for (i = 0; i <= MAX_KEY_ID; i++)
    {
        tmp = keybit[1] & ((u64)1<<i);
        if (tmp == 0)
            return i+64;
    }

    return keyid;
}

/*s32 vc_check_tmp_keyid(s32 keyid)
{
    s32 res = 0;

    if (keyid <= MAX_KEY_ID || keyid > MAX_TMP_KEY_ID)
        return -ERR_KEYID;

    s32 i;
    i = keyid - MAX_KEY_ID - 1;

    if (tmp_key[i].flag == 0 &&
        tmp_key[i].keyMac == NULL &&
        tmp_key[i].keydata == NULL)
        return -ERR_KEY_NULL;

    return res;
}

s32 vc_check_keyid(s32 keyid)
{
    s32 res = 0;

    u64 flag = 0;

    if (keyid > MAX_KEY_ID || keyid <= 0)
        return -ERR_KEYID;

    if (keyid < 64)
        flag = keybit[0] & ((u64)1<<keyid);
    else
        flag = keybit[1] & ((u64)1<<(keyid - 64));

    if (flag == 0)
    {
        VC_LOG_D("key not exist\n");
        return -ERR_KEY_NULL;
    }

    return res;
}*/

s32 vc_check_tmp_keymac(u8 keyid, u8 *keyMacIn)
{
    s32 res = 0;

    if (keyid <= MAX_KEY_ID || keyid > MAX_TMP_KEY_ID)
        return -ERR_KEYID;

    u8 tmpid;
    tmpid = keyid - 1 - MAX_KEY_ID;
    u8 *keyMac = tmp_key[tmpid].keyMac;

    if (keyMac == NULL || keyMacIn == NULL)
        return -ERR_PARAM;

    res = memcmp(keyMac, keyMacIn, 32);
    if (res != 0)
        return -ERR_AUTH;

    return res;
}

s32 vc_check_keymac(FILE *fp ,u8 *keyMac)
{
    s32 res = 0;

    if (fp == NULL)
        return -ERR_PARAM;

    u8 tmpbuf[33] = {0};
    res = fread(tmpbuf, 33 , 1, fp);

    if (keyMac == NULL)
        return -ERR_UNDEF;

    res = memcmp(keyMac, tmpbuf, 32);
    if (res != 0)
        return -ERR_AUTH;

    return res;
}

s32 do_gen_keymac(vc_input_info *keyInfo, u8 *keymac, u8 keyid)
{
    s32 res = 0;

    u8 out0 = keyInfo->data[0];
    keyInfo->data[0] = keyid;
    vc_hash_st hashInfo;
    hashInfo.hash_type = HASH_MD_SHA256;

    vc_output_info macout;
    macout.data = keymac;
    macout.dataSize = 32;
    res = vc_hash(&hashInfo, (vc_input_info *)keyInfo, &macout);
    keyInfo->data[0] = out0;

    return res;
}

s32 do_storage_tmp_key(vc_storage_key_info *storageKeyInfo, s32 isDelete)
{
    s32 res = 0;
    u8 tmpid = 0;

    vc_gen_key_info *keyInfo;

    if (storageKeyInfo == NULL)
    {
        return -ERR_PARAM;
    }

    keyInfo = &storageKeyInfo->keyInfo;

    if (keyInfo->keyID == 0)                //new key
    {
        keyInfo->keyID = vc_return_tmp_keyid();
        if (keyInfo->keyID <= MAX_KEY_ID || keyInfo->keyID > MAX_TMP_KEY_ID)
            return -ERR_KEYID;  //key错误*/
        res = do_gen_keymac((vc_input_info *)&storageKeyInfo->keyData, keyInfo->keyMac, keyInfo->keyID);
        if (res != 0)
        {
            VC_LOG_E("do_storage_tmp_key do_gen_keymac %d\n", res);
        }
    }
    else
    {
        res = vc_check_tmp_keymac(keyInfo->keyID, keyInfo->keyMac);
        if (res != 0)
        {
           goto exit;
        }

        if (isDelete == 0)       //update mac
        {
            res = do_gen_keymac((vc_input_info *)&storageKeyInfo->keyData, keyInfo->keyMac, keyInfo->keyID);
            if (res != 0)
            {
                VC_LOG_E("do_storage_tmp_key update do_gen_keymac %d\n", res);
            }
        }
    }
    tmpid = keyInfo->keyID - 1 - MAX_KEY_ID;

    if (isDelete == 0)
    {
        tmp_key[tmpid].flag = 1;
        tmp_key[tmpid].type = keyInfo->key_type;
        tmp_key[tmpid].keyMac = (u8 *)malloc(32);
        if (storageKeyInfo->keyInfo.keyMac == NULL)
        {
            res = -ERR_PARAM;
            goto exit;
        }
        if (tmp_key[tmpid].keyMac == NULL)
        {
            res = -ERR_MALLOC;
            goto exit;
        }
        memcpy(tmp_key[tmpid].keyMac, keyInfo->keyMac, 32);
        if (storageKeyInfo->keyData.data == NULL)
        {
            res = -ERR_PARAM;
            goto exit;
        }
        tmp_key[tmpid].keydata = (u8 *)malloc(storageKeyInfo->keyData.dataSize);
        if (tmp_key[tmpid].keydata == NULL)
        {
            res = -ERR_MALLOC;
            goto exit;
        }
        memcpy(tmp_key[tmpid].keydata, storageKeyInfo->keyData.data, storageKeyInfo->keyData.dataSize);
        tmp_key[tmpid].keylen = storageKeyInfo->keyData.dataSize;
    }
    else
    {
        tmp_key[tmpid].flag = 0;
        tmp_key[tmpid].type = 0;
        if (tmp_key[tmpid].keyMac != NULL)
        {
            free(tmp_key[tmpid].keyMac);
            tmp_key[tmpid].keyMac = NULL;
        }
        if (tmp_key[tmpid].keydata != NULL)
        {
            free(tmp_key[tmpid].keydata);
            tmp_key[tmpid].keydata = NULL;
        }
        tmp_key[tmpid].keylen = 0;
    }

exit:
    if (tmp_key[tmpid].keyMac != NULL && tmp_key[tmpid].keydata == NULL)
    {
        tmp_key[tmpid].flag = 0;
        free(tmp_key[tmpid].keyMac);
        tmp_key[tmpid].keyMac = NULL;
    }
    return res;
}

s32 do_storage_key(vc_storage_key_info *storageKeyInfo, s32 isDelete)
{
    s32 res = 0;
    FILE *fp = NULL;
    u8 tmpstr2[128] = {0};
    u8 tmpstr[16] = {0};
   // u8 oldmac[32] = {0};
    vc_input_info stoIn;
    stoIn.data = NULL;
    vc_output_info stoOut;
    stoOut.data = NULL;
    vc_gen_key_info *keyInfo;

    if (storageKeyInfo == NULL)
    {
        return -ERR_PARAM;
    }

    keyInfo = &storageKeyInfo->keyInfo;

    res = vc_set_keybit();
    if (res != 0)
    {
        VC_LOG_E("open dir error %d\n", res);
        return -ERR_PARAM;
    }

    if (keyInfo->keyID == 0)                //new key
    {
        keyInfo->keyID = vc_return_file_keyid();
        if (keyInfo->keyID <= 0 || keyInfo->keyID > MAX_KEY_ID)
            return -ERR_KEYID;  //key错误*/
        res = do_gen_keymac((vc_input_info *)&storageKeyInfo->keyData, keyInfo->keyMac, keyInfo->keyID);
        if (res != 0)
        {
            VC_LOG_E("do_storage_key do_gen_keymac %d\n", res);
        }

        sprintf(tmpstr2, "%s/%s%d", KEY_FILE_PATH, KEY_FILE_NAME, keyInfo->keyID);
        fp = fopen(tmpstr2, "wb");
        if (fp == NULL)
        {
            VC_LOG_E("write key file error0 %s\n ", tmpstr2);
            res = -ERR_PARAM;
            goto exit;
        }

        res = 0;
    }
    else   // key exist
    {
        sprintf(tmpstr2, "%s/%s%d", KEY_FILE_PATH, KEY_FILE_NAME, keyInfo->keyID);
        fp = fopen(tmpstr2, "rb");
        if (fp == NULL)
        {
            VC_LOG_E("write key file error1 %s\n ", tmpstr2);
            res = -ERR_PARAM;
            goto exit;
        }

        res = vc_check_keymac(fp, keyInfo->keyMac);     // auth
        if (res != 0)
        {
           goto exit;
        }
        if (isDelete == 0)       //update mac
        {
            res = do_gen_keymac((vc_input_info *)&storageKeyInfo->keyData, keyInfo->keyMac, keyInfo->keyID);
            if (res != 0)
            {
                VC_LOG_E("do_storage_key update do_gen_keymac %d\n", res);
            }
        }
    }

    if (isDelete == 0)
    {
        fwrite(keyInfo->keyMac, 32, 1, fp);
        tmpstr[0] = '\n';
        fwrite(tmpstr, 1, 1, fp);

        sprintf(tmpstr, "type = %d\n", keyInfo->key_type);
        fwrite(tmpstr, strlen(tmpstr), 1, fp);
        if (storageKeyInfo->isWhiteBoxEnc == 0)
        {
            stoIn.data = storageKeyInfo->keyData.data;
            stoIn.dataSize = storageKeyInfo->keyData.dataSize;
            if (stoIn.dataSize != 0)
                stoOut.data = (u8 *)malloc(stoIn.dataSize + 16);

            if (stoOut.data == NULL)
            {
                VC_LOG_E("vc_storage_key stoOut malloc error %d\n", storageKeyInfo->keyData.dataSize + 16);
                res = -ERR_MALLOC;
                goto exit;
            }

            vc_white_box_enc(&stoIn, &stoOut);
            fwrite(stoOut.data, stoOut.dataSize, 1, fp);
        }
        else
        {
            fwrite(storageKeyInfo->keyData.data, storageKeyInfo->keyData.dataSize, 1, fp);
        }
    }
    else
    {
        fclose(fp);
        sprintf(tmpstr2, "%s/%s%d", KEY_FILE_PATH, KEY_FILE_NAME, keyInfo->keyID);
        fp  = fopen(tmpstr2, "wb");
        if (fp == NULL)
        {
            VC_LOG_E("write key file error2 %s\n ", tmpstr2);
            res = -ERR_PARAM;
            goto exit;
        }
        fclose(fp);
        fp = NULL;
        res = remove(tmpstr2);
        if (res != 0)
        {
            VC_LOG_E("cannot remove file\n");
            goto exit;
        }
    }

exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    if (stoOut.data != NULL)
    {
        free(stoOut.data);
        stoOut.data = NULL;
    }

    return res;
}


s32 do_export_key(vc_except_key *exceptKeyInfo,vc_output_info* outputInfo)
{
    s32 res = 0;
#ifndef INIT_SO_ENABLE
    s32 keyID;
    s32 keyType;
    u8 keyPath[128] = {0};
    FILE *fp = NULL;

    if (exceptKeyInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;
    }

    if (exceptKeyInfo->KeyID <= 0 || exceptKeyInfo->KeyID > MAX_TMP_KEY_ID)
        return -ERR_KEYID;  //key错误

    s32 isfile = 0;
    keyID = exceptKeyInfo->KeyID;
    if (keyID <= MAX_KEY_ID)
        isfile = 1;

    if (isfile == 1)
    {
        sprintf(keyPath, "%s/%s%d", KEY_FILE_PATH, KEY_FILE_NAME, keyID);
        fp  = fopen(keyPath, "rb");
        if (fp == NULL)
        {
            VC_LOG_E("open error \n");
            return -ERR_PARAM; //key不存在
        }

        res = vc_check_keymac(fp, NULL);  //skip auth, read mac

        keyType = vc_get_key_type(fp);
        if (keyType < 0)
        {
            res = keyType;
            goto exit;
        }
  //      if (keyType == KEY_TYPE_RSA_PRIV || keyType == KEY_TYPE_SM2_PRIV || keyType == KEY_TYPE_ECC_PRIV)
        if (keyType == KEY_TYPE_SM2_PRIV || keyType == KEY_TYPE_ECC_PRIV)
        {
            res = -ERR_EXPORT_PRIV; //私钥不允许导出
            goto exit;
        }

        res = vc_get_key_data(fp, outputInfo);
        if (res < 0)
        {
            res = -ERR_KEY_READ; //key读取错误
            goto exit;
        }

        u32 orilen = outputInfo->dataSize;
        vc_white_box_decrypt((vc_input_info*)outputInfo, outputInfo);

        vc_input_info keyIn;
        keyIn.data = outputInfo->data;
        keyIn.dataSize = outputInfo->dataSize;

        outputInfo->dataSize = orilen;
        switch (exceptKeyInfo->trans_mod)
        {
            case TRANS_CIPHER_AES:
            {
                vc_aes_encdec_st *aesEncDecIn = (vc_aes_encdec_st *)(exceptKeyInfo->EncInfo);
                vc_aes_encdec_info aesEncDecInfo = {0};
                aesEncDecInfo.keyInfo.keyID = aesEncDecIn->keyID;
                aesEncDecInfo.keyInfo.key_type = KEY_TYPE_AES;
                aesEncDecInfo.aes_enc_mode = aesEncDecIn->aes_enc_mode;
                aesEncDecInfo.aes_padding_mode = aesEncDecIn->aes_padding_mode;
                aesEncDecInfo.iv = aesEncDecIn->iv;

                res = vc_aes_crypt(&aesEncDecInfo, &keyIn, outputInfo, OPT_ENC);//vc_aes_encrypt(aesEncDecInfo, &keyIn, outputInfo);
                if (res != 0)
                    goto exit;
            }
            break;

            case TRANS_CIPHER_RSA:
            {
                vc_rsa_encdec_st *rsaEncDecInfo = (vc_rsa_encdec_st *)(exceptKeyInfo->EncInfo);
                res = vc_rsa_encrypt(rsaEncDecInfo, &keyIn, outputInfo);
                if (res != 0)
                    goto exit;
            }
            break;

           /* case TRANS_CIPHER_P_DBG:
            {
                outputInfo->dataSize = keyIn.dataSize;
            }
            break;*/

            default:
                res = -ERR_SWITH;
        }
    }
    else
    {
        u8 tmpid = keyID - 1 - MAX_KEY_ID;
        if (tmp_key[tmpid].flag == 0)
            res = -ERR_KEYID;

        keyType = tmp_key[tmpid].type & 0xff;
      //  if (keyType == KEY_TYPE_RSA_PRIV || keyType == KEY_TYPE_SM2_PRIV || keyType == KEY_TYPE_ECC_PRIV)
        if (keyType == KEY_TYPE_SM2_PRIV || keyType == KEY_TYPE_ECC_PRIV)
        {
            res = -ERR_EXPORT_PRIV; //私钥不允许导出
            goto exit;
        }

        if (tmp_key[tmpid].keydata == NULL)
            return -ERR_KEY_READ;
        memcpy(outputInfo->data, tmp_key[tmpid].keydata, tmp_key[tmpid].keylen);
        outputInfo->dataSize = tmp_key[tmpid].keylen;
    }

exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
#endif
    return res;
}

s32 do_hmac_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *outdata)
{
    s32 res = 0;
    if (genKeyInfo == NULL || outdata == NULL)
        return -ERR_PARAM;

    res = vc_random_gen(genKeyInfo->keyLen, outdata);
    if (res != 0)
    {
        VC_LOG_E("do_hmac_genkey, vc_random_gen %d\n", res);
        return res;
    }

    genKeyInfo->keyID = 0;

    return res;
}


s32 do_sym_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *outdata)
{
    s32 res = 0;
#ifndef INIT_SO_ENABLE
    if (genKeyInfo == NULL || outdata == NULL)
        return -ERR_PARAM;


    switch (genKeyInfo->key_type)
    {
        case KEY_TYPE_AES:
        {
            if (genKeyInfo->keyLen != 16 && genKeyInfo->keyLen != 24 && genKeyInfo->keyLen != 32)  //128 192 256
            {
                return -ERR_KEYLEN;
            }
        }
        break;
        case KEY_TYPE_SM4:
        {
            if (genKeyInfo->keyLen != 16)
            {
                return -ERR_KEYLEN;
            }
        }
        break;

        default:
            return -ERR_KEYLEN; //key长度错误
    }

    res = vc_random_gen(genKeyInfo->keyLen, outdata);
    if (res != 0)
    {
        VC_LOG_E("gen sym key error\n", res);
        return res;
    }
    genKeyInfo->keyID = 0;
#endif
    return res;
}


s32 do_asym_genkey(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey)
{
    s32 res = 0;
#ifndef INIT_SO_ENABLE
    if (genKeyInfo == NULL || pubKey == NULL || privKey == NULL)
        return -ERR_PARAM;

    switch (genKeyInfo->key_type)
    {
        case KEY_TYPE_RSA_PRIV:
        case KEY_TYPE_RSA_PUB:
        {
            res = vc_gen_rsa_key(genKeyInfo,  pubKey, privKey);
        }
        break;

        #ifdef SMENABLE
        case KEY_TYPE_SM2_PUB:
        case KEY_TYPE_SM2_PRIV:
        {
            res = vc_gen_gm_key(genKeyInfo, pubKey, privKey);
        }
        break;
        #endif

        case KEY_TYPE_ECC_PUB:
        case KEY_TYPE_ECC_PRIV:
        {
            res = vc_gen_ecc_key(genKeyInfo, pubKey, privKey);
        }
        break;

        case KEY_TYPE_ECDH_25519:
        {
            res = vc_gen_ecdh_25519_key(genKeyInfo, pubKey, privKey);
        }
        break;

        default:
            return -ERR_KEYLEN; //key长度错误
    }

    if (res != 0)
    {
        VC_LOG_E("gen asym key error\n", res);
        return res;
    }

    genKeyInfo->keyID = 0;
#endif
    return res;
}

