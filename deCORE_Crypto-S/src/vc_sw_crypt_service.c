#include "../include/vc_sw_crypt_service.h"
#include "../include/vc_rsa.h"
#include "../include/vc_sm2.h"
#include "../include/vc_sm4.h"
#include "../include/vc_aes.h"
#include "../include/vc_hash.h"
#include "../include/vc_key.h"
#include "../include/vc_mac.h"
#include "../include/openssl/sm3.h"
#include "../include/vc_ecc.h"
#include "../include/vc_crt.h"
#include "../include/vc_envelope.h"

#include <stdio.h>
#include <string.h>

//#define READ_MAX  (64)

static vc_output_info* macout = NULL;

s32 vc_init(vc_get_info f, vc_output_info* out)
{
    s32 res = 0;

    if (macout == NULL)
    {
        macout = (vc_output_info *)malloc(sizeof(vc_output_info));
        if (macout == NULL)
            return -ERR_MALLOC;
        macout->data = (u8 *)malloc(64);
        if (macout == NULL)
            return -ERR_MALLOC;
        macout->dataSize = 64;
    }

    if (f == NULL || out == NULL)
        res = -ERR_PARAM;

    res = f(out);
    if (res != 0)
        return res;

    HASH_ALG htype;
    htype = HASH_MD_SHA256;
    res = vc_kdf(htype, (vc_input_info *)out, 64*8, macout);
    if (res != 0)
        return res;

    u8 tmpStr[128] = {0};
    FILE *fp;
    sprintf(tmpStr, "%s%s", MAC_FILE_PATH, MAC_FILE_NAME);
    fp = fopen(tmpStr ,"rb");
    if (fp == NULL)
        return -ERR_PARAM;

    vc_output_info macbuf;
    macbuf.data = tmpStr;
    macbuf.dataSize = sizeof(tmpStr);
    res = vc_get_key_data(fp, &macbuf);
    if (res < 0)
        goto exit;

    vc_white_box_decrypt((vc_input_info*)&macbuf, &macbuf);

    vc_or_data_add((vc_input_info *)&macbuf, macout);
exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    return res;
}

s32 vc_delete_initso(u8 *filepath)
{
    return remove(filepath);
}

s32 vc_aes_encrypt(vc_aes_encdec_st* aesInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_aes_encdec_info aesEncDecInfo = {0};
    if (aesInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    aesEncDecInfo.keyInfo.keyID = aesInfo->keyID;
    aesEncDecInfo.keyInfo.key_type = KEY_TYPE_AES;
    aesEncDecInfo.aes_enc_mode = aesInfo->aes_enc_mode;
    aesEncDecInfo.aes_padding_mode = aesInfo->aes_padding_mode;
    aesEncDecInfo.iv = aesInfo->iv;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    if (aesInfo->aes_enc_mode == AES_ENC_GCM)
    {
        if (aesInfo->gcm == NULL)
            return -ERR_PARAM;

        aesEncDecInfo.addData = aesInfo->gcm->addData;
        aesEncDecInfo.addLen = aesInfo->gcm->addLen;
        memcpy(aesEncDecInfo.tagBuf, aesInfo->gcm->tagBuf, 16);
        memcpy(aesEncDecInfo.tagVerify, aesInfo->gcm->tagVerify, 16);
    }

    res = vc_aes_crypt(&aesEncDecInfo, inputInfo, outputInfo, OPT_ENC);
    if (res == 0 && aesInfo->aes_enc_mode == AES_ENC_GCM)
    {
        if (aesInfo->gcm == NULL)
            return -ERR_PARAM;

        aesEncDecInfo.addData = aesInfo->gcm->addData;
        aesEncDecInfo.addLen = aesInfo->gcm->addLen;
        memcpy(aesInfo->gcm->tagBuf, aesEncDecInfo.tagBuf, 16);
        memcpy(aesInfo->gcm->tagVerify, aesEncDecInfo.tagVerify, 16);
    }
    return res;
}

s32 vc_aes_decrypt(vc_aes_encdec_st* aesInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_aes_encdec_info aesEncDecInfo = {0};
    if (aesInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    aesEncDecInfo.keyInfo.keyID = aesInfo->keyID;
    aesEncDecInfo.keyInfo.key_type = KEY_TYPE_AES;
    aesEncDecInfo.aes_enc_mode = aesInfo->aes_enc_mode;
    aesEncDecInfo.aes_padding_mode = aesInfo->aes_padding_mode;
    aesEncDecInfo.iv = aesInfo->iv;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    if (aesInfo->aes_enc_mode == AES_ENC_GCM)
    {
        if (aesInfo->gcm == NULL)
            return -ERR_PARAM;

        aesEncDecInfo.addData = aesInfo->gcm->addData;
        aesEncDecInfo.addLen = aesInfo->gcm->addLen;
        memcpy(aesEncDecInfo.tagBuf, aesInfo->gcm->tagBuf, 16);
        memcpy(aesEncDecInfo.tagVerify, aesInfo->gcm->tagVerify, 16);
    }

    res = vc_aes_crypt(&aesEncDecInfo, inputInfo, outputInfo, OPT_DEC);
    if (res != 0)
        return res;

    return res;
}

#ifdef SMENABLE
s32 vc_sm4_encrypt(vc_sm4_encdec_st* sm4Info, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_sm4_encdec_info sm4EncDecInfo = {0};
    if (sm4Info == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    sm4EncDecInfo.keyInfo.keyID = sm4Info->keyID;
    sm4EncDecInfo.keyInfo.key_type = KEY_TYPE_SM4;
    sm4EncDecInfo.sm4_enc_mode = sm4Info->enc_mode;
    sm4EncDecInfo.padding_mode = sm4Info->padding_mode;
    sm4EncDecInfo.iv = sm4Info->iv;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm4_crypt(&sm4EncDecInfo, inputInfo, outputInfo, OPT_ENC);
    return res;
}

s32 vc_sm4_decrypt(vc_sm4_encdec_st* sm4Info, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_sm4_encdec_info sm4EncDecInfo = {0};
    if (sm4Info == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    sm4EncDecInfo.keyInfo.keyID = sm4Info->keyID;
    sm4EncDecInfo.keyInfo.key_type = KEY_TYPE_SM4;
    sm4EncDecInfo.sm4_enc_mode = sm4Info->enc_mode;
    sm4EncDecInfo.padding_mode = sm4Info->padding_mode;
    sm4EncDecInfo.iv = sm4Info->iv;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm4_crypt(&sm4EncDecInfo, inputInfo, outputInfo, OPT_DEC);

    return res;
}
#endif

/***********************************************/
s32 vc_random_gen(u32 ran_len,vc_output_info* outputInfo)
{
    s32 res = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const s8 *pers = "rsa_encrypt";


    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    res = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const u8 *) pers,
                                 strlen( pers ) );
    if (res != 0)
    {
        VC_LOG_E("vc_random_gen mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }

    res = mbedtls_ctr_drbg_random(&ctr_drbg, outputInfo->data, ran_len);
    if (res == 0)
        outputInfo->dataSize = ran_len;
    else
        VC_LOG_E("vc_random_gen mbedtls_ctr_drbg_random error %d\n", res);

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return res;
}

s32 vc_rsa_encrypt(vc_rsa_encdec_st* encInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_encdec_info rsaEncDecInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    rsaEncDecInfo.keyInfo.keyID = encInfo->keyID;
    rsaEncDecInfo.keyInfo.key_type = KEY_TYPE_ECC_PUB;
    rsaEncDecInfo.rsa_padding_mode = encInfo->rsa_padding_mode;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_rsa_encrypt(&rsaEncDecInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_rsa_decrypt(vc_rsa_encdec_st* encInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_encdec_info rsaEncDecInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    rsaEncDecInfo.keyInfo.keyID = encInfo->keyID;
    rsaEncDecInfo.keyInfo.key_type = KEY_TYPE_ECC_PRIV;
    rsaEncDecInfo.rsa_padding_mode = encInfo->rsa_padding_mode;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_rsa_decrypt(&rsaEncDecInfo, inputInfo, outputInfo);
    return res;
}

s32 vc_rsa_sign(vc_rsa_sigver_st *sigInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_sigver_info rsaSigVerInfo = {0};
    if (sigInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    rsaSigVerInfo.hash_type = sigInfo->hash_type;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.keyID = sigInfo->encinfo.keyID;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.key_type = KEY_TYPE_ECC_PRIV;
    rsaSigVerInfo.rsa_encdec_info.rsa_padding_mode = sigInfo->encinfo.rsa_padding_mode;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_rsa_sign(&rsaSigVerInfo, inputInfo, outputInfo, 0);

    return res;
}

s32 vc_rsa_verify(vc_rsa_sigver_st * sigInfo, vc_input_info* inputInfo, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_sigver_info rsaSigVerInfo = {0};
    if (sigInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    rsaSigVerInfo.hash_type = sigInfo->hash_type;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.keyID = sigInfo->encinfo.keyID;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.key_type = KEY_TYPE_ECC_PUB;
    rsaSigVerInfo.rsa_encdec_info.rsa_padding_mode = sigInfo->encinfo.rsa_padding_mode;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_rsa_verify(&rsaSigVerInfo, inputInfo, outputInfo, 0);

    return res;
}

s32 vc_rsa_sign_file(vc_rsa_sigver_st * sigInfo, u8* filePath, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_sigver_info rsaSigVerInfo = {0};
    if (sigInfo == NULL)
        return -ERR_PARAM;

    rsaSigVerInfo.hash_type = sigInfo->hash_type;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.keyID = sigInfo->encinfo.keyID;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.key_type = KEY_TYPE_ECC_PRIV;
    rsaSigVerInfo.rsa_encdec_info.rsa_padding_mode = sigInfo->encinfo.rsa_padding_mode;

    res = do_rsa_sign(&rsaSigVerInfo, filePath, outputInfo, 1);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo->data;
        tmpout.dataSize = outputInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_rsa_verify_file(vc_rsa_sigver_st * sigInfo, u8* filePath, vc_output_info* outputInfo)
{
    s32 res = 0;

    vc_rsa_sigver_info rsaSigVerInfo = {0};
    if (sigInfo == NULL)
        return -ERR_PARAM;

    rsaSigVerInfo.hash_type = sigInfo->hash_type;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.keyID = sigInfo->encinfo.keyID;
    rsaSigVerInfo.rsa_encdec_info.keyInfo.key_type = KEY_TYPE_ECC_PUB;
    rsaSigVerInfo.rsa_encdec_info.rsa_padding_mode = sigInfo->encinfo.rsa_padding_mode;

    res = do_rsa_verify(&rsaSigVerInfo, filePath, outputInfo, 1);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo->data;
        tmpout.dataSize = outputInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_ecdsa_sign(vc_ecc_sigver_st *sigInfo, vc_input_info* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2)
{
    s32 res = 0;

    vc_ecc_sigver_info eccSigVerInfo = {0};
    if (sigInfo == NULL || inInfo == NULL || inInfo->data == NULL)
        return -ERR_PARAM;

    eccSigVerInfo.hash_type = sigInfo->hash_type;
    eccSigVerInfo.keyInfo.keyID = sigInfo->keyID;
    eccSigVerInfo.keyInfo.key_type = KEY_TYPE_ECC_PRIV;

    vc_output_info tmpout;
    tmpout.data = inInfo->data;
    tmpout.dataSize = inInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_ecdsa_sign(&eccSigVerInfo, inInfo, outputInfo1, outputInfo2, 0);

    return res;
}

s32 vc_ecdsa_verify(vc_ecc_sigver_st *sigInfo, vc_input_info* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2)
{
    s32 res = 0;

    vc_ecc_sigver_info eccSigVerInfo = {0};
    if (sigInfo == NULL || inInfo == NULL || inInfo->data == NULL)
        return -ERR_PARAM;

    eccSigVerInfo.hash_type = sigInfo->hash_type;
    eccSigVerInfo.keyInfo.keyID = sigInfo->keyID;
    eccSigVerInfo.keyInfo.key_type = KEY_TYPE_ECC_PUB;

    vc_output_info tmpout;
    tmpout.data = inInfo->data;
    tmpout.dataSize = inInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_ecdsa_verify(&eccSigVerInfo, inInfo, outputInfo1, outputInfo2, 0);

    return res;
}

s32 vc_ecdsa_sign_file(vc_ecc_sigver_st *sigInfo, u8* filePath, vc_output_info* outputInfo1, vc_output_info* outputInfo2)
{
    s32 res = 0;

    vc_ecc_sigver_info eccSigVerInfo = {0};
    if (sigInfo == NULL)
        return -ERR_PARAM;

    eccSigVerInfo.hash_type = sigInfo->hash_type;
    eccSigVerInfo.keyInfo.keyID = sigInfo->keyID;
    eccSigVerInfo.keyInfo.key_type = KEY_TYPE_ECC_PRIV;

    res = do_ecdsa_sign(&eccSigVerInfo, filePath, outputInfo1, outputInfo2, 1);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo1->data;
        tmpout.dataSize = outputInfo1->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_ecdsa_verify_file(vc_ecc_sigver_st *sigInfo, u8* filePath, vc_output_info* outputInfo1, vc_output_info* outputInfo2)
{
    s32 res = 0;

    vc_ecc_sigver_info eccSigVerInfo = {0};
    if (sigInfo == NULL)
        return -ERR_PARAM;

    eccSigVerInfo.hash_type = sigInfo->hash_type;
    eccSigVerInfo.keyInfo.keyID = sigInfo->keyID;
    eccSigVerInfo.keyInfo.key_type = KEY_TYPE_ECC_PUB;

    res = do_ecdsa_verify(&eccSigVerInfo, filePath, outputInfo1, outputInfo2, 1);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo1->data;
        tmpout.dataSize = outputInfo1->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_ecdh_shared_key(vc_input_info *privInfo, vc_input_info *pubInfo , vc_output_info* outputInfo)
{
    s32 res = 0;

    if (privInfo == NULL
|| privInfo->data == NULL)
        return -ERR_PARAM;

    vc_output_info tmpout;
    tmpout.data = privInfo->data;
    tmpout.dataSize = privInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_get_dhKey(privInfo, pubInfo, outputInfo);

    return res;
}

s32 vc_hash_file(vc_hash_st *hashInfo, u8* inputFile,  vc_output_info* outputInfo)
{
    s32 res = 0;

    FILE * fin = NULL;
    if (hashInfo == NULL || inputFile == NULL || outputInfo == NULL || outputInfo->data == NULL)
    {
        return -ERR_PARAM;
    }

    fin = fopen(inputFile, "rb");
    if (fin == NULL)
    {
        res = -ERR_PARAM;
        goto exit;
    }

    switch (hashInfo->hash_type)
    {
        case HASH_MD_SHA1:
        {
            if (outputInfo->dataSize < 20)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sha1(fin, outputInfo);
        }
        break;

        case HASH_MD_SHA224:
        {
            if (outputInfo->dataSize < 32)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sha224(fin, outputInfo, 1);
        }
        break;

        case HASH_MD_SHA256:
        {
            if (outputInfo->dataSize < 32)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sha224(fin, outputInfo, 0);
        }
        break;

        case HASH_MD_SHA384:
        {
            if (outputInfo->dataSize < 64)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sha384(fin, outputInfo, 1);
        }
        break;

        case HASH_MD_SHA512:
        {
            if (outputInfo->dataSize < 64)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sha384(fin, outputInfo, 0);
        }
        break;

        #ifdef SMENABLE
        case HASH_SM3:
        {
            if (outputInfo->dataSize < 32)
            {
                res = -ERR_NOT_ENOUGH;
                goto exit;
            }
            hash_file_sm3(fin, outputInfo);
        }
        break;
        #endif

        default:
        {
            res = -ERR_SWITH;
            goto exit;
        }
    }

exit:
    if (fin != NULL)
    {
        fclose(fin);
        fin = NULL;
    }

    return res;
}

#ifdef SMENABLE
s32 vc_sm2_enc(vc_sm2_encdec_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 res = 0;

    vc_sm2_encdec_info sm2encInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    sm2encInfo.keyInfo.keyID = encInfo->keyID;
    sm2encInfo.keyInfo.key_type = KEY_TYPE_SM2_PUB;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm2_enc(&sm2encInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_sm2_dec(vc_sm2_encdec_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 res = 0;

    vc_sm2_encdec_info sm2encInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    sm2encInfo.keyInfo.keyID = encInfo->keyID;
    sm2encInfo.keyInfo.key_type = KEY_TYPE_SM2_PUB;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm2_dec(&sm2encInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_sm2_sign(vc_sm2_sigver_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 res = 0;

    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    vc_sm2_sigver_info sm2sigverInfo = {0};

    sm2sigverInfo.keyInfo.keyID = encInfo->keyID;
    sm2sigverInfo.keyInfo.key_type = KEY_TYPE_SM2_PUB;
    sm2sigverInfo.id = encInfo->id;

    sm2sigverInfo.skeyInfo.keyID = encInfo->skeyID;
    sm2sigverInfo.skeyInfo.key_type = KEY_TYPE_SM2_PRIV;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm2_sign(&sm2sigverInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_sm2_verify(vc_sm2_sigver_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 res = 0;

    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    vc_sm2_sigver_info sm2sigverInfo = {0};

    sm2sigverInfo.keyInfo.keyID = encInfo->keyID;
    sm2sigverInfo.keyInfo.key_type = KEY_TYPE_SM2_PUB;
    sm2sigverInfo.id = encInfo->id;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_sm2_verify(&sm2sigverInfo, inputInfo, outputInfo);

    return res;
}
#endif

s32 vc_ecc_enc(vc_ecc_encdec_st * encInfo, vc_input_info * inputInfo, vc_output_info * outputInfo)
{
    s32 res = 0;

    vc_ecc_encdec_info eccEncDecInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    eccEncDecInfo.hash_type = encInfo->hash_type;
    eccEncDecInfo.keyInfo.keyID = encInfo->keyID;
    eccEncDecInfo.keyInfo.key_type = KEY_TYPE_ECC_PUB;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_ecc_enc(&eccEncDecInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_ecc_dec(vc_ecc_encdec_st * encInfo, vc_input_info * inputInfo, vc_output_info * outputInfo)
{
    s32 res = 0;

    vc_ecc_encdec_info eccEncDecInfo = {0};
    if (encInfo == NULL || inputInfo == NULL || inputInfo->data == NULL)
        return -ERR_PARAM;

    eccEncDecInfo.hash_type = encInfo->hash_type;
    eccEncDecInfo.keyInfo.keyID = encInfo->keyID;
    eccEncDecInfo.keyInfo.key_type = KEY_TYPE_ECC_PRIV;

    vc_output_info tmpout;
    tmpout.data = inputInfo->data;
    tmpout.dataSize = inputInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_ecc_dec(&eccEncDecInfo, inputInfo, outputInfo);

    return res;
}

s32 vc_hash(vc_hash_st *hashInfo, vc_input_info*  inputInfo,  vc_output_info* outputInfo)
{
    s32 res = 0;

    if (hashInfo == NULL || inputInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;
    }

    switch (hashInfo->hash_type)
    {
        case HASH_MD_SHA1:
        {
            if (outputInfo->dataSize < 20)
            {
                return -ERR_NOT_ENOUGH;
            }
            mbedtls_sha1(inputInfo->data, inputInfo->dataSize, outputInfo->data);
            outputInfo->dataSize = 20;
        }
        break;

        case HASH_MD_SHA256:
        {
            if (outputInfo->dataSize < 32)
            {
                return -ERR_NOT_ENOUGH;
            }
            mbedtls_sha256(inputInfo->data, inputInfo->dataSize, outputInfo->data, 0);
            outputInfo->dataSize = 32;
        }
        break;

        case HASH_MD_SHA224:
        {
            if (outputInfo->dataSize < 32)
            {
                return -ERR_NOT_ENOUGH;
            }
            mbedtls_sha256(inputInfo->data, inputInfo->dataSize, outputInfo->data, 1);
            outputInfo->dataSize = 32;
        }
        break;

        case HASH_MD_SHA384:
        {
            if (outputInfo->dataSize < 64)
            {
                return -ERR_NOT_ENOUGH;
            }
            mbedtls_sha512(inputInfo->data, inputInfo->dataSize, outputInfo->data, 1);
            outputInfo->dataSize = 64;
        }
        break;

        case HASH_MD_SHA512:
        {
            if (outputInfo->dataSize < 64)
            {
                return -ERR_NOT_ENOUGH;
            }
            mbedtls_sha512(inputInfo->data, inputInfo->dataSize, outputInfo->data, 0);
            outputInfo->dataSize = 64;
        }
        break;

        #ifdef SMENABLE
        case HASH_SM3:
        {
            if (outputInfo->dataSize < 32)
            {
                return -ERR_NOT_ENOUGH;
            }
            sm3(inputInfo->data, inputInfo->dataSize, outputInfo->data);
            outputInfo->dataSize = 32;
        }
        break;
        #endif

        default:
            return -ERR_SWITH;
    }

    return res;
}

s32 vc_storage_key(vc_storage_key_st *storageInfo)
{
    s32 res = 0;

    vc_storage_key_info storageKeyInfo = {0};
    if (storageInfo == NULL)
        return -ERR_PARAM;

    storageKeyInfo.isWhiteBoxEnc = storageInfo->isWhiteBoxEnc;
    storageKeyInfo.keyData.data = storageInfo->keyData.data;
    storageKeyInfo.keyData.dataSize = storageInfo->keyData.dataSize;
    storageKeyInfo.keyInfo.keyID = storageInfo->keyID;
    storageKeyInfo.keyInfo.keyMac = storageInfo->keyMac;
    storageKeyInfo.keyInfo.key_type = storageInfo->keyType;

    vc_output_info tmpout;
    tmpout.data = storageKeyInfo.keyData.data;
    tmpout.dataSize = storageKeyInfo.keyData.dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_key(&storageKeyInfo, 0);
    if (res == 0)
        storageInfo->keyID = storageKeyInfo.keyInfo.keyID;

    return res;
}

s32 vc_delete_key(vc_storage_key_st * storageInfo)
{
    s32 res = 0;

    vc_storage_key_info storageKeyInfo = {0};
    if (storageInfo == NULL)
        return -ERR_PARAM;

    storageKeyInfo.keyInfo.keyID = storageInfo->keyID;
    storageKeyInfo.keyInfo.keyMac = storageInfo->keyMac;

    vc_output_info tmpout;
    tmpout.data = storageKeyInfo.keyInfo.keyMac;
    tmpout.dataSize = 32;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_key(&storageKeyInfo, 1);

    return res;
}

s32 vc_export_key(vc_except_key_st *exceptKeyInfo,vc_output_info* outputInfo)
{
    s32 res = 0;
    res = do_export_key((vc_except_key *)exceptKeyInfo, outputInfo);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo->data;
        tmpout.dataSize = outputInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_storage_tmp_key(vc_storage_key_st * storageInfo)
{
    s32 res = 0;

    vc_storage_key_info storageKeyInfo = {0};
    if (storageInfo == NULL)
        return -ERR_PARAM;

    storageKeyInfo.keyData.data = storageInfo->keyData.data;
    storageKeyInfo.keyData.dataSize = storageInfo->keyData.dataSize;
    storageKeyInfo.keyInfo.keyID = storageInfo->keyID;
    storageKeyInfo.keyInfo.keyMac = storageInfo->keyMac;
    storageKeyInfo.keyInfo.key_type = storageInfo->keyType;

    vc_output_info tmpout;
    tmpout.data = storageKeyInfo.keyData.data;
    tmpout.dataSize = storageKeyInfo.keyData.dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_tmp_key(&storageKeyInfo, 0);
    if (res == 0)
        storageInfo->keyID = storageKeyInfo.keyInfo.keyID;

    return res;
}

s32 vc_delete_tmp_key(vc_storage_key_st * storageInfo)
{
    s32 res = 0;

    vc_storage_key_info storageKeyInfo = {0};
    if (storageInfo == NULL)
        return -ERR_PARAM;

    storageKeyInfo.keyInfo.keyID = storageInfo->keyID;
    storageKeyInfo.keyInfo.keyMac = storageInfo->keyMac;

    vc_output_info tmpout;
    tmpout.data = storageKeyInfo.keyInfo.keyMac;
    tmpout.dataSize = 32;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_tmp_key(&storageKeyInfo, 1);

    return res;
}

s32 vc_export_tmp_key(vc_except_key_st *exceptKeyInfo,vc_output_info* outputInfo)
{
    s32 res = 0;
    res = do_export_key((vc_except_key *)exceptKeyInfo, outputInfo);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo->data;
        tmpout.dataSize = outputInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}


s32 vc_hmac_genkey(vc_gen_key_st *genKey,  vc_output_info *outdata)
{
    s32 res = 0;

    vc_gen_key_info keyInfo = {0};
    if (genKey == NULL)
        return -ERR_PARAM;

    keyInfo.keyLen = genKey->keyLen;
    keyInfo.key_type = genKey->keyType;

    res = do_hmac_genkey(&keyInfo, outdata);

    return res;
}

s32 vc_cmac_genkey(vc_gen_key_st *genKey,  vc_output_info *outdata)
{
    s32 res = 0;

    vc_gen_key_info keyInfo = {0};
    if (genKey == NULL)
        return -ERR_PARAM;

    keyInfo.keyLen = genKey->keyLen;
    keyInfo.key_type = genKey->keyType;

    res = do_hmac_genkey(&keyInfo, outdata);

    return res;
}

s32 vc_sym_genkey(vc_gen_key_st *genKey,  vc_output_info *outdata)
{
    s32 res = 0;

    vc_gen_key_info keyInfo = {0};
    if (genKey == NULL)
        return -ERR_PARAM;

    keyInfo.keyLen = genKey->keyLen;
    keyInfo.key_type = genKey->keyType;

    res = do_sym_genkey(&keyInfo, outdata);

    return res;
}

s32 vc_asym_genkey(vc_gen_key_st *genKey,  vc_output_info *pubKey, vc_output_info *privKey)
{
    s32 res = 0;

    vc_gen_key_info keyInfo = {0};
    if (genKey == NULL)
        return -ERR_PARAM;

    keyInfo.keyLen = genKey->keyLen;
    keyInfo.key_type = genKey->keyType;
    keyInfo.keyInfo = genKey->extInfo;

    res = do_asym_genkey(&keyInfo, pubKey, privKey);

    return res;
}

s32 vc_CalcCmac(vc_input_info     *input,  vc_cmac_st *mackey, vc_output_info *cmac)
{
    s32 res = 0;

    vc_cmac_info cmac_info;
    if (mackey == NULL || input == NULL || input->data == NULL)
        return -ERR_PARAM;

    cmac_info.keyInfo.keyID = mackey->keyID;

    vc_output_info tmpout;
    tmpout.data = input->data;
    tmpout.dataSize = input->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_CalcCmac(input, &cmac_info, cmac);

    return res;
}

s32 vc_VerifyCmac(vc_input_info     *input,  vc_cmac_st *mackey, vc_output_info *cmac)
{
    s32 res = 0;
    if (mackey == NULL || input == NULL || input->data == NULL)
        return -ERR_PARAM;

    vc_output_info tmpout;
    tmpout.data = input->data;
    tmpout.dataSize = input->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_VerifyCmac(input, mackey, cmac);

    return res;
}

s32 vc_CalcHmac(vc_hmac_st *hmackey, vc_input_info *input, vc_output_info *hmac)
{
    s32 res = 0;

    vc_hmac_info hmac_info;
    if (hmackey == NULL || input == NULL || input->data == NULL)
        return -ERR_PARAM;

    hmac_info.hash_type = hmackey->hash_type;
    hmac_info.keyInfo.keyID = hmackey->keyID;

    vc_output_info tmpout;
    tmpout.data = input->data;
    tmpout.dataSize = input->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_CalcHmac(&hmac_info, input, hmac);

    return res;
}

s32 vc_Base64Encode(vc_input_info *input, vc_output_info *output)
{
    s32 res = 0;
    s32 len = 0;

    if (input == NULL || output == NULL)
    {
        return -ERR_PARAM;
    }

    res = mbedtls_base64_encode(output->data, output->dataSize, (size_t *)&len, input->data, input->dataSize);
	if (res != 0)
    {
        VC_LOG_E("vc_Base64Encode failed %d\n", res);
        return res;
    }
    output->dataSize = len;

    return res;
}

s32 vc_Base64Decode(vc_input_info *input, vc_output_info *output)
{
    s32 res = 0;
    s32 len = 0;

    if (input == NULL || output == NULL)
    {
        return -ERR_PARAM;
    }

    res = mbedtls_base64_decode(output->data, output->dataSize, (size_t *)&len, input->data, input->dataSize);
	if (res != 0)
    {
        VC_LOG_E("vc_Base64Encode failed %d\n", res);
        return res;
    }
    output->dataSize = len;

    return res;
}

s32 vc_parse_crt_pubkey(u8 crtID, vc_output_info *outInfo)
{
    s32 res = 0;
    u8 filePath[128] = {0};
    u32 fileSize = 0;

    sprintf(filePath, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crtID);
    fileSize = vc_get_file_size(filePath);
    if (fileSize == -1)
        return -ERR_PARAM;

    vc_input_info info;
    info.data = (u8 *)malloc(fileSize);
    if (info.data == NULL)
    {
        return -ERR_MALLOC;
    }
    info.dataSize = fileSize;

    res = do_get_crt(crtID, (vc_output_info *)&info);
    if (res != 0)
    {
        goto exit;
    }

    res = do_parse_crt_pubkey(&info, outInfo);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outInfo->data;
        tmpout.dataSize = outInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

exit:
    if (info.data != NULL)
    {
        free(info.data);
        info.data = NULL;
    }

    return res;
}

s32 vc_verify_crt(vc_input_info *crtInfo, u8 caID, u8 crlID, u8 *cn)
{
    s32 res = 0;

    vc_input_info caInfo = {0};
    vc_input_info crlInfo = {0};

    u8 filePath[128] = {0};
    u32 caFileSize = 0;
    u32 crlFileSize = 0;

    sprintf(filePath, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, caID);
    caFileSize = vc_get_file_size(filePath);
    if (caFileSize == -1)
        return -ERR_PARAM;


    caInfo.data = (u8 *)malloc(caFileSize);
    if (caInfo.data == NULL)
    {
        return -ERR_MALLOC;
    }
    caInfo.dataSize = caFileSize;

    if (crtInfo == NULL || crtInfo == NULL)
        return -ERR_PARAM;

    vc_output_info tmpout;
    tmpout.data = crtInfo->data;
    tmpout.dataSize = crtInfo->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_get_crt(caID, (vc_output_info *)&caInfo);
    if (res != 0)
    {
        goto exit;
    }

    if (crlID != 0)
    {
        sprintf(filePath, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crlID);
        crlFileSize = vc_get_file_size(filePath);
        if (crlFileSize == -1)
        {
            res = -ERR_PARAM;
            goto exit;
        }

        crlInfo.data = (u8 *)malloc(crlFileSize);
        if (crlInfo.data == NULL)
        {
            res = -ERR_MALLOC;
            goto exit;
        }
        crlInfo.dataSize = crlFileSize;

        res = do_get_crt(crlID, (vc_output_info *)&crlInfo);
        if (res != 0)
        {
            goto exit;
        }

        res = do_verify_crt(crtInfo, &caInfo, &crlInfo, cn);
    }
    else
        res = do_verify_crt(crtInfo, &caInfo, NULL, cn);


exit:
    if (caInfo.data != NULL)
    {
        free(caInfo.data);
        caInfo.data = NULL;
    }
    if (crlInfo.data != NULL)
    {
        free(crlInfo.data);
        crlInfo.data = NULL;
    }

    return res;
}

s32 vc_gen_csr(vc_csr_st * csrInfo, vc_output_info * output)
{
    s32 res = 0;
    res = do_gen_csr((vc_csr *)csrInfo, output);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = output->data;
        tmpout.dataSize = output->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}

s32 vc_storage_crt(vc_storage_crt_st * storageCrtInfo)
{
    s32 res = 0;

    if (storageCrtInfo->crtData.data == NULL)
        return -ERR_PARAM;

    vc_output_info tmpout;
    tmpout.data = storageCrtInfo->crtData.data;
    tmpout.dataSize = storageCrtInfo->crtData.dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_crt((vc_storage_crt_info *)storageCrtInfo, 0);

    return res;
}

s32 vc_delete_crt(vc_storage_crt_st * storageCrtInfo)
{
    s32 res = 0;

    if (storageCrtInfo->crtMac == NULL)
        return -ERR_PARAM;

    vc_output_info tmpout;
    tmpout.data = storageCrtInfo->crtMac;
    tmpout.dataSize = 32;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_storage_crt((vc_storage_crt_info *)storageCrtInfo, 1);

    return res;
}

s32 vc_export_crt(vc_except_crt_st *crtInfo,vc_output_info* outputInfo)
{
    s32 res = 0;

    res = do_export_crt((vc_except_crt *)crtInfo, outputInfo);
    if (res == 0)
    {
        vc_output_info tmpout;
        tmpout.data = outputInfo->data;
        tmpout.dataSize = outputInfo->dataSize;
        vc_sub_data_or((vc_input_info *)macout, &tmpout);
    }

    return res;
}


/*
s32 vc_whitebox_enc_data(vc_input_info *input, void *outfile)
{
    s32 res = 0;
    res = vc_whitebox_with_data(input, outfile, 0);
    return res;
}

s32 vc_whitebox_dec_data(vc_input_info *input, void *output)
{
    s32 res = 0;
    res = vc_whitebox_with_data(input, output, 1);
    return res;
}

s32 vc_whitebox_enc_file(u8 *infile, void *outfile)
{
    s32 res = 0;
    res = vc_whitebox_with_file(infile, outfile, 0);
    return res;
}

s32 vc_whitebox_dec_file(u8 *infile, void *output)
{
    s32 res = 0;
    res = vc_whitebox_with_file(infile, output, 1);
    return res;
}
*/

s32 vc_enveloped_seal(vc_envelope_in_st *envelope, vc_input_info *input, vc_envelope_out_st *output)  // not support gcm
{
    s32 res = 0;

    vc_envelop_info envIn = {0};
    if (envelope == NULL ||output == NULL || input == NULL || input->data == NULL)
        return -ERR_PARAM;

    envIn.keyInfo.keyID = envelope->keyID;
    envIn.aesInfo.keyInfo.keyLen = envelope->aesKeyLen;
    envIn.aesInfo.keyInfo.key_type = KEY_TYPE_AES;
    envIn.aesInfo.aes_enc_mode = envelope->aes_enc_mode;
    envIn.aesInfo.iv = envelope->iv;

    if (envelope->aes_enc_mode == AES_ENC_GCM)
        return -ERR_SWITH;

    vc_envelop_info envOut = {0};

    envOut.cipher.data = output->cipher.data;
    envOut.cipher.dataSize = output->cipher.dataSize;
    envOut.aesKeyCipher.data = output->aeskeycipher.data;
    envOut.aesKeyCipher.dataSize = output->aeskeycipher.dataSize;

    vc_output_info tmpout;
    tmpout.data = input->data;
    tmpout.dataSize = input->dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_seal(&envIn, input, &envOut);
    if (res == 0)
    {
        output->cipher.dataSize = envOut.cipher.dataSize;
        output->aeskeycipher.dataSize = envOut.aesKeyCipher.dataSize;
    }

    return res;
}

s32 vc_enveloped_openseal(vc_envelope_out_st *envInfo, vc_output_info *output)
{
    s32 res = 0;

    vc_envelop_info envIn = {0};
    if (envInfo == NULL || envInfo->cipher.data == NULL)
        return -ERR_PARAM;

    envIn.keyInfo.keyID = envInfo->keyID;
    envIn.aesInfo.aes_enc_mode = envInfo->aes_enc_mode;
    envIn.aesInfo.iv = envInfo->iv;

    envIn.cipher.data = envInfo->cipher.data;
    envIn.cipher.dataSize = envInfo->cipher.dataSize;
    envIn.aesKeyCipher.data = envInfo->aeskeycipher.data;
    envIn.aesKeyCipher.dataSize = envInfo->aeskeycipher.dataSize;

    if (envInfo->aes_enc_mode == AES_ENC_GCM)
        return -ERR_SWITH;

    vc_output_info tmpout;
    tmpout.data = envInfo->cipher.data;
    tmpout.dataSize = envInfo->cipher.dataSize;
    vc_sub_data_or((vc_input_info *)macout, &tmpout);

    res = do_openseal(&envIn, output);

    return res;
}

