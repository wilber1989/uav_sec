#include "../include/vc_rsa.h"
#include "../include/vc_key.h"

#define EXPONENT (65537)

//for origin data (u8 array)
#if 0
void vc_init_key_str(RSA_CONTEXT_STRING *keyString)
{
    memset(keyString, 0, sizeof(RSA_CONTEXT_STRING));
}

void vc_free_key_str(RSA_CONTEXT_STRING *keyString)
{
    if (keyString->N != NULL)
    {
        free(keyString->N);
        keyString->N = NULL;
    }
    if (keyString->E != NULL)
    {
        free(keyString->E);
        keyString->E = NULL;
    }
    if (keyString->D != NULL)
    {
        free(keyString->D);
        keyString->D = NULL;
    }
    if (keyString->P != NULL)
    {
        free(keyString->P);
        keyString->P = NULL;
    }
    if (keyString->Q != NULL)
    {
        free(keyString->Q);
        keyString->Q = NULL;
    }
    if (keyString->DP != NULL)
    {
        free(keyString->DP);
        keyString->DP = NULL;
    }
    if (keyString->DQ != NULL)
    {
        free(keyString->DQ);
        keyString->DQ = NULL;
    }
    if (keyString->QP != NULL)
    {
        free(keyString->QP);
        keyString->QP = NULL;
    }
}

s32 vc_rsa_get_pub_context(mbedtls_rsa_context* rsa,  vc_rsa_encdec_info* rsaEncDecInfo, RSA_CONTEXT_STRING * keyString)
{
    s32 res = 0;
    mbedtls_rsa_init(rsa, rsaEncDecInfo->rsa_padding_mode, rsaEncDecInfo->hash_id);

    rsa->len = rsaEncDecInfo->keyLen / 8;
    res = mbedtls_mpi_read_string(&(rsa->N) , 16, keyString->N);
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = mbedtls_mpi_read_string(&(rsa->E) , 16, keyString->E);
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = mbedtls_rsa_check_pubkey(rsa);
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    return res;
}

s32 vc_rsa_get_priv_context(mbedtls_rsa_context* rsa,  vc_rsa_encdec_info* rsaEncDecInfo, RSA_CONTEXT_STRING * keyString)
{
    s32 res = 0;
    mbedtls_rsa_init(rsa, rsaEncDecInfo->rsa_padding_mode, rsaEncDecInfo->hash_id);

    rsa->len = rsaEncDecInfo->keyLen / 8;
    res = ( mbedtls_mpi_read_string( &(rsa->N) , 16, keyString->N));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->E) , 16, keyString->E ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

     res = ( mbedtls_mpi_read_string( &(rsa->D) , 16, keyString->D ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->P) , 16, keyString->P ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->Q) , 16, keyString->Q ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->DP) , 16, keyString->DP ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->DQ) , 16, keyString->DQ ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = ( mbedtls_mpi_read_string( &(rsa->QP) , 16, keyString->QP ));
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    res = mbedtls_rsa_check_privkey(rsa);
    if(res != 0)
    {
        return res; // mbedtls_rsa_check_pubkey error
    }

    return res;
}


s32 vc_get_rsa_key(u32 keyBits, u8 * filePath, RSA_CONTEXT_STRING* keyInfo, s32 mod)
{
    s32 res = 0;
    FILE *fp;
    u32 buflen;
    u8 *tmpStr;
    u8 *tmp;
    u32 tmplen;
    vc_key_type keyType;
    vc_output_info outKey;

    buflen = MAX_RSA_BITS / 8 * 9 + 100; //key文件数据部分大小
    tmpStr = (u8 *)malloc(buflen);
    if (tmpStr == NULL)
    {
        return -10;
    }

    fp = fopen(filePath, "rb");
    if (fp == NULL)
    {
        printf("vc_get_rsa_pub_key open file error\n");
        return -3; //打开文件失败
    }

    keyType = vc_get_key_type(fp);
   // printf("22222222222 %d %d\n",mod, keyType);

    if ((mod == 0 && keyType != KEY_TYPE_RSA_PUB)
        || (mod == 1 && keyType != KEY_TYPE_RSA_PRIV))
    {
        res = -13; //key类型错误
        goto exit;
    }

    outKey.data = tmpStr;
    outKey.dataSize = buflen;
    memset(tmpStr, 0, buflen);
    res = vc_get_key_data(fp, &outKey);
    if (res < 0)
    {
        res = -9; //key读取错误
        goto exit;
    }

   /* vc_output_info outKey2;
    u8 tmpStr2[MAX_RSA_BITS / 4 * 9 + 100] = {0};
    outKey2.data = tmpStr2;*/

    vc_white_box_decrypt(&outKey, &outKey);
   // printf("my-----%s\n", outKey2.data);

    res = vc_file_str(outKey.data,  "N = ", keyBits/4+1, &(keyInfo->N));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "E = ", 6+1, &(keyInfo->E));
    if (res != 0)
    {
        goto exit;
    }

    if (mod == 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "D = ", keyBits/4+1, &(keyInfo->D));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "P = ", keyBits/8+1, &(keyInfo->P));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "Q = ", keyBits/8+1, &(keyInfo->Q));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "DP = ", keyBits/8+1, &(keyInfo->DP));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "DQ = ", keyBits/8+1, &(keyInfo->DQ));
    if (res != 0)
    {
        goto exit;
    }

    res = vc_file_str(outKey.data,  "QP = ", keyBits/8+1, &(keyInfo->QP));
    if (res != 0)
    {
        goto exit;
    }


    printf("NNN %s \n EEE %s \n", keyInfo->N ,keyInfo->E);
exit:
    fclose(fp);
    free(tmpStr);
    tmpStr = NULL;
    return res;
}

s32 vc_get_rsa_pub_key(u32 keyBits, u8 * filePath, RSA_CONTEXT_STRING* keyInfo)
{
    s32 res = 0;
    res = vc_get_rsa_key(keyBits, filePath, keyInfo, 0);

    return res;
}

s32 vc_get_rsa_priv_key(u32 keyBits, u8 * filePath, RSA_CONTEXT_STRING* keyInfo)
{
    s32 res = 0;
    res = vc_get_rsa_key(keyBits, filePath, keyInfo, 1);
    return 0;
}
#endif

s32 vc_get_rsa_key(u32 keyid, mbedtls_pk_context* keyInfo, s32 mod)
{
    s32 res = 0;
    FILE *fp = NULL;
    u32 buflen = 0;
    u8 *tmpStr = NULL;
    vc_key_type keyType;
    vc_output_info outKey;
    u8 tmpStr2[128];

    res = vc_set_keybit();
    if (res != 0)
    {
        VC_LOG_E("open dir error %d\n", res);
        return -ERR_PARAM;
    }

    sprintf(tmpStr2, "%s/KEY_%d", KEY_FILE_PATH, keyid);

    buflen = MAX_RSA_BITS / 8 * 9 + 100; //key文件数据部分大小
    tmpStr = (u8 *)malloc(buflen);
    if (tmpStr == NULL)
    {
        return -ERR_MALLOC;
    }

    fp = fopen(tmpStr2, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("vc_get_rsa_pub_key open file error\n");
        res = -ERR_PARAM; //打开文件失败
        goto exit;
    }

    res = vc_check_keymac(fp, NULL);

    keyType = vc_get_key_type(fp);

    if ((mod == 0 && keyType != KEY_TYPE_RSA_PUB)
        || (mod == 1 && keyType != KEY_TYPE_RSA_PRIV))
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    outKey.data = tmpStr;
    outKey.dataSize = buflen;
    memset(tmpStr, 0, buflen);
    res = vc_get_key_data(fp, &outKey);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    vc_white_box_decrypt((vc_input_info*)&outKey, &outKey);

    mbedtls_pk_init(keyInfo);
    if (mod == 0)
        res = mbedtls_pk_parse_public_key(keyInfo, outKey.data, outKey.dataSize);
    else
        res = mbedtls_pk_parse_key(keyInfo, outKey.data, outKey.dataSize , NULL ,0);

exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    if (tmpStr != NULL)
    {
        free(tmpStr);
        tmpStr = NULL;
    }
    return res;
}

s32 vc_get_tmp_rsa_key(u8 keyid, mbedtls_pk_context* keyInfo, s32 mod)
{
    s32 res = 0;
    u32 buflen = 0;
    u8 *tmpStr = NULL;

    vc_key_type keyType;

    res = vc_check_tmp_keymac(keyid, NULL);

    keyType = vc_get_tmp_key_type(keyid);

    if ((mod == 0 && keyType != KEY_TYPE_RSA_PUB)
        || (mod == 1 && keyType != KEY_TYPE_RSA_PRIV))
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    buflen = MAX_RSA_BITS / 8 * 9 + 100; //key文件数据部分大小
    tmpStr = (u8 *)malloc(buflen);
    if (tmpStr == NULL)
    {
        return -ERR_MALLOC;
    }

    vc_input_info outKey;
    outKey.data = tmpStr;
    outKey.dataSize = buflen;
    memset(tmpStr, 0, buflen);
    res = vc_get_tmp_key_data(keyid, (vc_output_info*)&outKey);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    mbedtls_pk_init(keyInfo);
    if (mod == 0)
        res = mbedtls_pk_parse_public_key(keyInfo, outKey.data, outKey.dataSize);
    else
        res = mbedtls_pk_parse_key(keyInfo, outKey.data, outKey.dataSize , NULL ,0);
exit:
    if (tmpStr != NULL)
    {
        free(tmpStr);
        tmpStr = NULL;
    }
    return res;
}


s32 vc_get_rsa_pub_key(u32 keyid, mbedtls_pk_context* keyInfo)
{
    s32 res = 0;
    if (keyid <= MAX_KEY_ID)
        res = vc_get_rsa_key(keyid, keyInfo, 0);
    else
        res = vc_get_tmp_rsa_key(keyid, keyInfo, 0);

    return res;
}


s32 vc_get_rsa_priv_key(u32 keyid, mbedtls_pk_context* keyInfo)
{
    s32 res = 0;
    if (keyid <= MAX_KEY_ID)
        res = vc_get_rsa_key(keyid, keyInfo, 1);
    else
        res = vc_get_tmp_rsa_key(keyid, keyInfo, 1);

    return res;
}

s32 do_rsa_encrypt(vc_rsa_encdec_info* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;
    mbedtls_rsa_context *rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const s8 *pers = "rsa_encrypt";
    vc_gen_key_info *keyInfo;

    if (rsaEncDecInfo == NULL || inputInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }

    keyInfo = &rsaEncDecInfo->keyInfo;

    mbedtls_pk_context keyInf;

    res = vc_get_rsa_pub_key(keyInfo->keyID, &keyInf);
    if(res != 0)
    {
        return res; // key 获取失败
    }

    rsa = (mbedtls_rsa_context *) keyInf.pk_ctx;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const u8 *) pers,
                                 strlen( pers ) );
    if (res != 0)
    {
        goto exit;
    }

    switch (rsaEncDecInfo->rsa_padding_mode)
    {
        case RSA_PKCS_V15:
        case RSA_PKCS_V21:
        {
           res = mbedtls_rsa_pkcs1_encrypt( rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, inputInfo->dataSize, inputInfo->data, outputInfo->data );
           if(res != 0)
           {
               goto exit; // mbedtls_rsa_check_pubkey error
           }
           outputInfo->dataSize = rsa->len;
        }
        break;

        default:
            return -ERR_SWITH;
    }

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free(&keyInf);
    return res;
}


s32 do_rsa_decrypt(vc_rsa_encdec_info* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;
    mbedtls_rsa_context *rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const s8 *pers = "rsa_encrypt";
    vc_gen_key_info *keyInfo;

    if (rsaEncDecInfo == NULL || inputInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }

    keyInfo = &rsaEncDecInfo->keyInfo;

    mbedtls_pk_context keyInf;
    res = vc_get_rsa_priv_key(keyInfo->keyID, &keyInf);
    if(res != 0)
    {
        return res; // key 获取失败
    }

    /*res = vc_rsa_get_priv_context(rsa, rsaEncDecInfo, &keyString);
    if (res != 0)
    {
        goto exit;
    }*/
    rsa = (mbedtls_rsa_context *) keyInf.pk_ctx;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const u8 *) pers,
                                 strlen( pers ) );
    if (res != 0)
    {
        goto exit;
    }

    switch (rsaEncDecInfo->rsa_padding_mode)
    {
        case RSA_PKCS_V15:
        case RSA_PKCS_V21:
        {
            res = mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, (size_t *)&(outputInfo->dataSize), inputInfo->data, outputInfo->data, outputInfo->dataSize);
            if (res != 0)
            {
                goto exit; // mbedtls_rsa_check_pubkey error
            }
        }
        break;

        default:
            return -ERR_SWITH;
    }

exit:
   // vc_free_key_str(&keyString);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free(&keyInf);

    //mbedtls_rsa_free( &rsa );

    return res;
}

s32 do_rsa_sign(vc_rsa_sigver_info * rsaSigVerInfo, void* inInfo, vc_output_info* outputInfo, s32 mod)
{
    s32 res = 0;
    vc_rsa_encdec_info rsaEncDecInfo;
    mbedtls_rsa_context *rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const s8 *pers = "rsa_encrypt";
    u8 hashSum[64] = {0};
    vc_output_info hashout;
    hashout.data = hashSum;
    hashout.dataSize = 64;
    vc_input_info *inputInfo;
    u8 *filePath;
    vc_gen_key_info *keyInfo;

    if (rsaSigVerInfo == NULL || inInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }

    if (mod == 0)
        inputInfo = (vc_input_info *)inInfo;
    else
        filePath = (u8 *)inInfo;

    rsaEncDecInfo = rsaSigVerInfo->rsa_encdec_info;

    keyInfo = &rsaEncDecInfo.keyInfo;

    mbedtls_pk_context keyInf;
    res = vc_get_rsa_priv_key(keyInfo->keyID, &keyInf);
    if(res != 0)
    {
        return -ERR_GET_KEY; // key 获取失败
    }

    rsa = (mbedtls_rsa_context *) keyInf.pk_ctx;

    vc_hash_st hashInfo;
    hashInfo.hash_type = rsaSigVerInfo->hash_type;
    if (mod == 0)
        res = vc_hash(&hashInfo, inputInfo, &hashout);
    else
        res = vc_hash_file(&hashInfo, filePath, &hashout);
    if (res != 0)
    {
        VC_LOG_E("rsa sign hash error %d\n",res);
        goto exit;
    }

    switch (rsaEncDecInfo.rsa_padding_mode)
    {
        case RSA_PKCS_V15:
        case RSA_PKCS_V21:
        {
            mbedtls_ctr_drbg_init( &ctr_drbg );
            mbedtls_entropy_init( &entropy );

            res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                         &entropy, (const u8 *) pers,
                                         strlen( pers ) );
            if (res != 0)
            {
                goto exit;
            }
            rsa->padding = rsaEncDecInfo.rsa_padding_mode;
            rsa->hash_id = rsaSigVerInfo->hash_type;
            res = mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, rsaSigVerInfo->hash_type, 0, hashSum, outputInfo->data);
            if(res != 0)
            {
                goto exit;
            }
            outputInfo->dataSize = rsa->len;
        }
        break;

        default:
            return -ERR_SWITH;
    }

exit:
   // vc_free_key_str(&keyString);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free(&keyInf);
  //  mbedtls_rsa_free( &rsa );

    return res;
}

s32 do_rsa_verify(vc_rsa_sigver_info * rsaSigVerInfo, void* inInfo, vc_output_info* outputInfo, s32 mod)
{
    s32 res = 0;
    vc_rsa_encdec_info rsaEncDecInfo;
  //  RSA_CONTEXT_STRING keyString;
    mbedtls_rsa_context *rsa;
    u8 hashSum[64] = {0};
    vc_output_info hashout;
    hashout.data = hashSum;
    hashout.dataSize = 64;
    vc_input_info* inputInfo;
    u8 *filePath;
    vc_gen_key_info *keyInfo;

    if (rsaSigVerInfo == NULL || inInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;  //参数错误
    }

    if (mod == 0)
        inputInfo = (vc_input_info *)inInfo;
    else
        filePath = (u8 *)inInfo;

    rsaEncDecInfo = rsaSigVerInfo->rsa_encdec_info;

    keyInfo = &rsaEncDecInfo.keyInfo;

    mbedtls_pk_context keyInf;
    res = vc_get_rsa_pub_key(keyInfo->keyID, &keyInf);
    if(res != 0)
    {
        return -ERR_GET_KEY; // key 获取失败
    }

    rsa = (mbedtls_rsa_context *) keyInf.pk_ctx;
    vc_hash_st hashInfo;
    hashInfo.hash_type = rsaSigVerInfo->hash_type;
    if (mod == 0)
        res = vc_hash(&hashInfo, inputInfo, &hashout);
    else
        res = vc_hash_file(&hashInfo, filePath, &hashout);
    if (res != 0)
    {
        VC_LOG_E("rsa sign hash error %d\n",res);
        goto exit;
    }

    rsa->padding = rsaSigVerInfo->rsa_encdec_info.rsa_padding_mode;
    switch (rsaEncDecInfo.rsa_padding_mode)
    {
        case RSA_PKCS_V15:
		case RSA_PKCS_V21:
        {
            rsa->padding = rsaEncDecInfo.rsa_padding_mode;
            rsa->hash_id = rsaSigVerInfo->hash_type;
            res = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, rsaSigVerInfo->hash_type, 0, hashSum, outputInfo->data);
            if(res != 0)
            {
                VC_LOG_E("mbedtls_rsa_pkcs1_verify %x\n",res);
                goto exit;
            }
        }
        break;

        default:
            return -ERR_SWITH;
    }
exit:
  //  vc_free_key_str(&keyString);

    //mbedtls_rsa_free( &rsa );
    mbedtls_pk_free(&keyInf);

    return res;
}

s32 vc_gen_rsa_key(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey)
{
    s32 res = 0;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const s8 *pers = "rsa_encrypt";

    if (genKeyInfo->keyLen != 128 && genKeyInfo->keyLen != 256)  //1024 2048
    {
        return -ERR_KEYLEN;
    }


    int padding_mod = *((int *)(genKeyInfo->keyInfo));

    mbedtls_rsa_init(&rsa, padding_mod, 0);
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const u8 *) pers,
                                 strlen( pers ) );
    if (res != 0)
    {
        goto rsa_exit;
    }

    res = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, (genKeyInfo->keyLen * 8), EXPONENT);
    if (res != 0)
    {
        goto rsa_exit;
    }

    mbedtls_pk_context ctx_pk;
    mbedtls_pk_init(&ctx_pk);
    mbedtls_pk_info_t pkinfo;
    pkinfo.type = MBEDTLS_PK_RSA;
    ctx_pk.pk_info = &pkinfo;
    ctx_pk.pk_ctx = (void *)&rsa;
    //res = mbedtls_pk_parse_public_key(&ctx_pk, pubKey->data, pubKey->dataSize + 1);
    memset(pubKey->data, 0 ,pubKey->dataSize);
    res = mbedtls_pk_write_pubkey_pem(&ctx_pk, pubKey->data, 4096);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_pk_parse_public_key Can't import public key res %d\n", res);
    }
    pubKey->dataSize = strlen(pubKey->data) + 1;

    res = mbedtls_pk_write_key_pem(&ctx_pk, privKey->data, 4096);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_pk_parse_public_key Can't import public key res %d\n", res);
    }
    privKey->dataSize = strlen(privKey->data) + 1;


rsa_exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_rsa_free( &rsa );

    return res;
}


