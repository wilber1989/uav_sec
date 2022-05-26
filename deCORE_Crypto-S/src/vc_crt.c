#include "../include/vc_crt.h"
#include "../include/vc_key.h"
#include "../include/mbedtls/x509_crt.h"
#include "../include/mbedtls/x509_csr.h"

#include<dirent.h>
#include<sys/types.h>

/*
static mbedtls_x509_crt crtList_VERIFY;        // tobe verify
static mbedtls_x509_crt crtList_TRUST;        // trusted
static mbedtls_x509_crt crtList_CRL;        // CRL list*/

static u64 crtbit[2] = {0};

s32 vc_set_crtbit()
{
    s32 res = 0;

    DIR *dir;
    struct dirent *ptr = NULL;

    if ((dir = opendir(CRT_FILE_PATH)) == NULL)
    {
        VC_LOG_E("vc_set_crtbit can not open dir %s\n", CRT_FILE_PATH);
        return -ERR_PARAM; // open dir error
    }

    memset(crtbit, 0 ,sizeof(crtbit));

    while((ptr = readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)
            continue;
        else if ((ptr->d_type == 8) && (strstr(ptr->d_name,CRT_FILE_NAME) != NULL))  //8 == FILE
        {
            s8 *tmp;
            s32 keyid;
            tmp = ptr->d_name + 4;
            keyid = atoi(tmp);
            if (keyid <= 0 || keyid > MAX_CRT_ID)
                continue;
            if (keyid < 64)
                crtbit[0] |= ((u64)1<<keyid);
            else
                crtbit[1] |= ((u64)1<<(keyid - 64));
        }

    }
    res = closedir(dir);

    return res;
}

s32 vc_check_crtid(s32 keyid)
{
    s32 res = 0;

    u64 flag = 0;

    if (keyid > MAX_CRT_ID || keyid <= 0)
        return -ERR_KEYID;

    if (keyid < 64)
        flag = crtbit[0] & ((u64)1<<keyid);
    else
        flag = crtbit[1] & ((u64)1<<(keyid - 64));

    if (flag == 0)
    {
        VC_LOG_D("crt not exist\n");
        return -ERR_KEY_NULL;
    }

    return res;
}

s32 vc_return_crtid()
{
    s32 keyid = -1;

    if (crtbit[0] == 0xfffffffffffffffe && crtbit[1] == 0xffffffffffffffff)
    {
        VC_LOG_E("too many crt\n");
        return -1;
    }

    s32 i;
    u64 tmp = 0;
    for (i = 1; i < 64; i++)
    {
        tmp = crtbit[0] & ((u64)1<<i);
        if (tmp == 0)
            return i;
    }

    for (i = 0; i < 64; i++)
    {
        tmp = crtbit[1] & ((u64)1<<i);
        if (tmp == 0)
            return i+64;
    }

    return keyid;
}


s32 do_storage_crt(vc_storage_crt_info *crtInfo, s32 isDelete)
{
    s32 res = 0;

    vc_input_info stoIn;
    stoIn.data = NULL;
    vc_output_info stoOut;
    stoOut.data = NULL;

    FILE *fp = NULL;
    u8 tmpstr2[128] = {0};
    u8 tmpstr[16] = {0};

    if (crtInfo == NULL)
    {
        return -ERR_PARAM;
    }

    res = vc_set_crtbit();
    if (res != 0)
    {
        VC_LOG_E("open dir error %d\n", res);
        return -ERR_PARAM;
    }

    if (crtInfo->crtID == 0)                //new crt
    {
        crtInfo->crtID = vc_return_crtid();
        if (crtInfo->crtID <= 0 || crtInfo->crtID > MAX_CRT_ID)
            return -ERR_KEYID;  //crtid错误*/

        vc_input_info tmpin;
        tmpin.data = crtInfo->crtData.data;
        tmpin.dataSize = 32;
        res = do_gen_keymac((vc_input_info *)&tmpin, crtInfo->crtMac, crtInfo->crtID);
        if (res != 0)
        {
            VC_LOG_E("do_storage_crt do_gen_keymac %d\n", res);
        }
    }

    res = vc_check_crtid(crtInfo->crtID);

    sprintf(tmpstr2, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crtInfo->crtID);
    if (res == -ERR_KEY_NULL)
        fp = fopen(tmpstr2, "wb");
    else
        fp = fopen(tmpstr2, "rb");

    if (fp == NULL)
    {
        VC_LOG_E("write crt file error0 %s\n ", tmpstr2);
        res = -ERR_PARAM;
        goto exit;
    }

    if (isDelete == 0)
    {
        stoIn.data = crtInfo->crtData.data;
        stoIn.dataSize = crtInfo->crtData.dataSize;
        if (stoIn.dataSize != 0)
            stoOut.data = (u8 *)malloc(stoIn.dataSize + 16);

        if (stoOut.data == NULL)
        {
            VC_LOG_E("vc_storage_crt stoOut malloc error %d\n", crtInfo->crtData.dataSize + 16);
            res = -ERR_MALLOC;
            goto exit;
        }
    }

    if (res != -ERR_KEY_NULL)  // key exist , auth
    {
        res = vc_check_keymac(fp, crtInfo->crtMac);
        if (res != 0)
        {
           goto exit;
        }
        if (isDelete == 0)       //update mac
        {
            res = do_gen_keymac((vc_input_info *)&crtInfo->crtData, crtInfo->crtMac, crtInfo->crtID);
            if (res != 0)
            {
                VC_LOG_E("do_storage_crt update do_gen_keymac %d\n", res);
            }
        }
    }
    else
        res = 0;

    if (isDelete == 0)
    {
        fwrite(crtInfo->crtMac, 32, 1, fp);
        tmpstr[0] = '\n';
        fwrite(tmpstr, 1, 1, fp);

        if (crtInfo->isWhiteBoxEnc == 0)
        {
            vc_white_box_enc(&stoIn, &stoOut);
            fwrite(stoOut.data, stoOut.dataSize, 1, fp);
        }
        else
        {
            fwrite(crtInfo->crtData.data, crtInfo->crtData.dataSize, 1, fp);
        }
    }
    else
    {
        fclose(fp);
        sprintf(tmpstr2, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crtInfo->crtID);
        fp  = fopen(tmpstr2, "wb");
        if (fp == NULL)
        {
            VC_LOG_E("write crt file error0 %s\n ", tmpstr2);
            res = -ERR_PARAM;
            goto exit;
        }
        fclose(fp);
        fp = NULL;
        remove(tmpstr2);
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

s32 do_export_crt(vc_except_crt *crtInfo,vc_output_info* outputInfo)
{
    s32 res = 0;
    s32 crtID;
    u8 keyPath[128] = {0};

    if (crtInfo == NULL || outputInfo == NULL)
    {
        return -ERR_PARAM;
    }

    if (crtInfo->crtID <= 0 || crtInfo->crtID > MAX_CRT_ID)
        return -ERR_KEYID;  //key错误

    crtID = crtInfo->crtID;
    FILE *fp;
    sprintf(keyPath, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crtID);
    fp  = fopen(keyPath, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("open error \n");
        return -ERR_PARAM; //key不存在
    }

    res = vc_check_keymac(fp, NULL);  //skip auth, read mac

    res = vc_get_key_data(fp, outputInfo);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    u32 orilen = outputInfo->dataSize;
    vc_white_box_decrypt((vc_input_info*)outputInfo, outputInfo);

exit:
    fclose(fp);
    fp = NULL;

    return res;
}


s32 do_parse_crt(vc_input_info *crtbuf, void *crtList, s32 isCrt)
{
    s32 res = 0;

    if (crtbuf == NULL || crtList == NULL)
    {
        return -ERR_PARAM;
    }

    if (isCrt != 0)
    {
        mbedtls_x509_crt *crt = (mbedtls_x509_crt *)crtList;
        res = mbedtls_x509_crt_parse(crt, crtbuf->data, crtbuf->dataSize);
        if (res != 0)
        {
            VC_LOG_E("do_parse_crt mbedtls_x509_crt_parse err %d \n", res);
            goto exit;
        }
    }
    else
    {
        mbedtls_x509_crl *crl = (mbedtls_x509_crl *)crtList;
        res = mbedtls_x509_crl_parse(crl, crtbuf->data, crtbuf->dataSize);
        if (res != 0)
        {
            VC_LOG_E("do_parse_crl mbedtls_x509_crl_parse err %d \n", res);
            goto exit;
        }
    }

exit:
    return res;
}

s32 do_verify_crt(vc_input_info *crtInfo, vc_input_info *caInfo, vc_input_info *crlInfo, u8 *cn)
{
    s32 res = 0;
    u32 flags = 0;

    if (crtInfo == NULL || caInfo == NULL)
    {
        return -ERR_PARAM;
    }

    mbedtls_x509_crt crt_crt;
    mbedtls_x509_crt crt_ca;
    mbedtls_x509_crl crt_crl;
    mbedtls_x509_crl *pcrt_crl = NULL;

    mbedtls_x509_crt_init(&crt_crt);
    mbedtls_x509_crt_init(&crt_ca);

    res = do_parse_crt(crtInfo ,&crt_crt, 1);
    if (res != 0)
    {
        VC_LOG_E("do_verify_crt do_parse_crt_pubkey crt %d\n", res);
        goto exit;
    }

    res = do_parse_crt(caInfo ,&crt_ca, 1);
    if (res != 0)
    {
        VC_LOG_E("do_verify_crt do_parse_crt_pubkey ca %d\n", res);
        goto exit;
    }

    if (crlInfo != NULL)
    {
        mbedtls_x509_crl_init(&crt_crl);
        res = do_parse_crt(crlInfo ,&crt_crl, 0);
        if (res != 0)
        {
            VC_LOG_E("do_verify_crt do_parse_crt_pubkey crt_crl %d\n", res);
            goto exit;
        }
        pcrt_crl = &crt_crl;
    }

    res = mbedtls_x509_crt_verify(&crt_crt, &crt_ca, pcrt_crl, cn, &flags, NULL, NULL);
    if (res != 0)
    {
        VC_LOG_E("do_verify_crt mbedtls_x509_crt_verify  %d\n", res);
    }

exit:
    mbedtls_x509_crt_free(&crt_crt);
    mbedtls_x509_crt_free(&crt_ca);
    if (crlInfo != NULL)
    {
        mbedtls_x509_crl_free(&crt_crl);
        pcrt_crl = NULL;
    }
    return res;
}

s32 do_get_crt(u8 crtID, vc_output_info *outInfo)
{
    s32 res = 0;

    u8 keyPath[128] = {0};

    if (outInfo == NULL)
    {
        return -ERR_PARAM;
    }

    if (crtID <= 0 || crtID > MAX_CRT_ID)
        return -ERR_KEYID;  //key错误

    FILE *fp;
    sprintf(keyPath, "%s/%s%d", CRT_FILE_PATH, CRT_FILE_NAME, crtID);
    fp  = fopen(keyPath, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("open error \n");
        return -ERR_PARAM; //key不存在
    }

    res = vc_check_keymac(fp, NULL);  //skip auth, read mac

    res = vc_get_key_data(fp, outInfo);
    if (res < 0)
    {
        res = -ERR_KEY_READ; //key读取错误
        goto exit;
    }

    vc_white_box_decrypt((vc_input_info*)outInfo, outInfo);

exit:
    fclose(fp);
    fp = NULL;

    return res;
}

s32 do_parse_crt_pubkey(vc_input_info *crtbuf, vc_output_info *outInfo)
{
    s32 res = 0;
    mbedtls_x509_crt crtList;

    if (crtbuf == NULL || outInfo == NULL)
    {
        return -ERR_PARAM;
    }

    mbedtls_x509_crt_init(&crtList);

    res = do_parse_crt(crtbuf, &crtList, 1);
    if (res != 0)
    {
        VC_LOG_E("do_parse_crt_pubkey do_parse_crt error %d\n",res);
        goto exit;
    }

    res = mbedtls_pk_write_pubkey_pem(&(crtList.pk), outInfo->data, outInfo->dataSize);
    if (res != 0)
    {
        VC_LOG_E("do_parse_crt_pubkey mbedtls_pk_parse_public_key error %d\n",res);
        goto exit;
    }
    outInfo->dataSize = strlen(outInfo->data) + 1;
exit:
    mbedtls_x509_crt_free(&crtList);
    return res;
}

static s32 vc_get_key(u32 keyid, mbedtls_pk_context* keyInfo)
{
    s32 res = 0;
    FILE *fp = NULL;
    u32 buflen;
    u8 *tmpStr;
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

    buflen = MAX_RSA_BITS; //key文件数据部分大小
    tmpStr = (u8 *)malloc(buflen);
    if (tmpStr == NULL)
    {
        return -ERR_MALLOC;
    }

    fp = fopen(tmpStr2, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("vc_get_key open file error\n");
        res = -ERR_PARAM; //打开文件失败
        goto exit;
    }

    res = vc_check_keymac(fp, NULL); //skip mac

    keyType = vc_get_key_type(fp);
    if (keyType < 0)
        goto exit;

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
    res = mbedtls_pk_parse_key(keyInfo, outKey.data, outKey.dataSize, NULL, 0);

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

s32 do_gen_csr(vc_csr *csrInfo, vc_output_info *output)
{
    s32 res = 0;
    mbedtls_x509write_csr csr;
    mbedtls_pk_context key;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    if (csrInfo == NULL || output == NULL)
    {
        return -ERR_PARAM;
    }

    mbedtls_x509write_csr_init(&csr);

    mbedtls_x509write_csr_set_md_alg(&csr ,csrInfo->hashAlg);

    mbedtls_pk_init(&key);

    res = vc_get_key(csrInfo->keyID, &key);
    if (res != 0)
    {
        VC_LOG_E("do_gen_csr vc_get_pub_key %d err %d\n", csrInfo->keyID, res);
        goto exit;
    }
    mbedtls_x509write_csr_set_key(&csr, &key);

    res = mbedtls_x509write_csr_set_key_usage(&csr, csrInfo->key_usage);
    if (res != 0)
    {
        VC_LOG_E("do_gen_csr mbedtls_x509write_csr_set_key_usage err %d\n", res);
        goto exit;
    }

    res = mbedtls_x509write_csr_set_ns_cert_type(&csr, csrInfo->ns_cert_type);
    if (res != 0)
    {
        VC_LOG_E("do_gen_csr mbedtls_x509write_csr_set_ns_cert_type err %d\n", res);
        goto exit;
    }

    res = mbedtls_x509write_csr_set_subject_name(&csr, csrInfo->subject_name);
    if (res != 0)
    {
        VC_LOG_E("do_gen_csr mbedtls_x509write_csr_set_subject_name err %d\n", res);
        goto exit;
    }

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init(&ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                           &entropy,
                           (const unsigned char *) "csrgen",
                           strlen("csrgen")
                            );

    if (res != 0)
    {
        VC_LOG_E("do_ecdsa_sign mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }


    res = mbedtls_x509write_csr_pem(&csr, output->data, output->dataSize, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res != 0)
    {
        VC_LOG_E("do_gen_csr mbedtls_x509write_csr_pem err %d\n", res);
        goto exit;
    }
    output->dataSize = strlen(output->data) + 1;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_pk_free(&key);

    mbedtls_x509write_csr_free(&csr);
    return res;
}
