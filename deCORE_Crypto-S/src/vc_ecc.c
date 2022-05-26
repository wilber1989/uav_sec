#include "../include/vc_ecc.h"
#include "../include/mbedtls/ecdh.h"
#include "../include/vc_key.h"

#define DATAFLAG (0X08)
#define TMPOUTLEN (0X11)

#define POINT_BUF_MAX (270)

#if encodeECC
//for encode plain to ecc
static u8 MK[] = {0x03, 0xfc, 0xfd, 0xfe, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,0xfe};//0xf8};
#endif

void vc_mov_data(vc_input_info *buf, s32 valLen)
{
    if (buf == NULL)
        return ;

    s32 i,j;

    for (i = buf->dataSize - valLen, j = 0; j < valLen; j++, i++)
    {
        buf->data[j] = buf->data[i];
    }
    buf->dataSize = valLen;

    return ;
}

s32 vc_gen_ecc_key(vc_gen_key_info *genKeyInfo, vc_output_info *pubKey , vc_output_info *privKey)
{
    s32 res = 0;
    ecc_group_id id;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    if (genKeyInfo == NULL || privKey == NULL || pubKey == NULL)
    {
        return -ERR_PARAM;
    }

    id = *((ecc_group_id *)(genKeyInfo->keyInfo));
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECKEY;//MBEDTLS_PK_ECKEY_DH;//MBEDTLS_PK_ECDSA;

    mbedtls_pk_init(&key);
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(pk_alg));
    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecc_key mbedtls_pk_setup error %d\n", res);
        goto exit;
    }

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *) "ecdsa",
                               strlen("ecdsa")
                                );

    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecc_key mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }

    res = mbedtls_ecp_gen_key(id,
                              mbedtls_pk_ec(key),
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg
                            );
    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecc_key mbedtls_ecp_gen_key error %d\n", res);
        goto exit;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
    memset(pubKey->data, 0 ,pubKey->dataSize);

    res = mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_ecp_check_pubkey error %d\n", res);
        goto exit;
    }
    res = mbedtls_pk_write_pubkey_pem(&key, pubKey->data, 2048);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_pk_parse_public_key Can't import public key res %d\n", res);
        goto exit;
    }
   /* else
    {
        {
        int i;
        for (i = 0; i < strlen(pubKey->data); i++)
        {
            printf("0x%02x,", pubKey->data[i]);
        }
        printf("##################################xxxxxxxxx  %d\n", strlen(pubKey->data));
        }
    }*/
    pubKey->dataSize = strlen(pubKey->data) + 1;



    res = mbedtls_ecp_check_privkey(&ec->grp, &ec->d);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_ecp_check_privkey error %d\n", res);
        goto exit;
    }

    res = mbedtls_pk_write_key_pem(&key, privKey->data, 2048);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_pk_parse_public_key Can't import priv key res %d\n", res);
        goto exit;
    }
    /*else
    {
         {
        int i;
        for (i = 0; i < strlen(privKey->data); i++)
        {
            printf("0x%02x,", privKey->data[i]);
        }
        printf("##################################xxxxxxxxx00000  %d\n", strlen(privKey->data));
        }
    }*/
    privKey->dataSize = strlen(privKey->data) + 1;

exit:
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return res;
}

s32 vc_get_ecc_key(u32 keyid, mbedtls_pk_context* keyInfo, s32 mod)
{
    s32 res = 0;
    FILE *fp = NULL;
    u32 buflen;
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

    buflen = MAX_ECC_KEY /8 *9 +100; //key文件数据部分大小
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

    if ((mod == 0 && keyType != KEY_TYPE_ECC_PUB)
        || (mod == 1 && keyType != KEY_TYPE_ECC_PRIV))
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

s32 vc_get_tmp_ecc_key(u8 keyid, mbedtls_pk_context* keyInfo, s32 mod)
{
    s32 res = 0;
    u32 buflen = 0;
    u8 *tmpStr = NULL;

    vc_key_type keyType;

    res = vc_check_tmp_keymac(keyid, NULL);

    keyType = vc_get_tmp_key_type(keyid);

    if ((mod == 0 && keyType != KEY_TYPE_ECC_PUB)
        || (mod == 1 && keyType != KEY_TYPE_ECC_PRIV))
    {
        res = -ERR_KEY_TYPE; //key类型错误
        goto exit;
    }

    buflen = MAX_ECC_KEY / 8 * 9 + 100; //key文件数据部分大小
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



s32 do_ecdsa_sign(vc_ecc_sigver_info *sigInfo, void* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2, s32 mod)
{
    s32 res = 0;

    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    vc_input_info* inputInfo;
    u8 *filePath;
    u8 hashSum[64] = {0};
    vc_output_info hashout;
    hashout.data = hashSum;
    hashout.dataSize = 64;
    vc_gen_key_info *keyInfo;

    if (sigInfo == NULL || inInfo == NULL || outputInfo1 == NULL || outputInfo2 == NULL)
    {
        return -ERR_PARAM;
    }

    if (mod == 0)
        inputInfo = (vc_input_info *)inInfo;
    else
        filePath = (u8 *)inInfo;

    keyInfo = &sigInfo->keyInfo;

    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_ecc_key(keyInfo->keyID, &key, 1);
    else
        res = vc_get_tmp_ecc_key(keyInfo->keyID, &key, 1);
    if (res != 0)
    {
        return -ERR_GET_KEY;
    }

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
    res = mbedtls_ecp_check_privkey(&ec->grp, &ec->d);
    if(res != 0)
    {
        VC_LOG_E("do_ecdsa_sign mbedtls_ecp_check_privkey error %d\n", res);
        goto exit;
    }

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *) "ecdsa",
                               strlen("ecdsa")
                                );

    if (res != 0)
    {
        VC_LOG_E("do_ecdsa_sign mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }

    mbedtls_ecp_group *grp = &(ec->grp);

    mbedtls_mpi r,s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    vc_hash_st hashInfo;
    hashInfo.hash_type = sigInfo->hash_type;
    if (mod == 0)
        res = vc_hash(&hashInfo, inputInfo, &hashout);
    else
        res = vc_hash_file(&hashInfo, filePath, &hashout);
    if (res != 0)
    {
        VC_LOG_E("ecc sign hash error %d\n",res);
        goto exit;
    }

    res = mbedtls_ecdsa_sign(grp, &r, &s,
                &(ec->d), hashout.data, hashout.dataSize,
                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res != 0)
    {
        goto exit;
    }

    if (outputInfo1->dataSize < (r.n * 8) || outputInfo2->dataSize < (r.n * 8))
    {
        res = -ERR_NOT_ENOUGH;
        goto exit;
    }

    mbedtls_mpi_write_binary(&r, outputInfo1->data , outputInfo1->dataSize);

    vc_mov_data((vc_input_info *) outputInfo1, mbedtls_mpi_size(&r));
    mbedtls_mpi_write_binary(&s, outputInfo2->data , outputInfo2->dataSize);
    vc_mov_data((vc_input_info *) outputInfo2, mbedtls_mpi_size(&s));
exit:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return res;
}

s32 do_ecdsa_verify(vc_ecc_sigver_info *sigInfo, void* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2 ,s32 mod)
{
    s32 res = 0;

    mbedtls_pk_context key;
    vc_input_info* inputInfo;
    u8 *filePath;
    u8 hashSum[64] = {0};
    vc_output_info hashout;
    hashout.data = hashSum;
    hashout.dataSize = 64;
    vc_gen_key_info *keyInfo;

    if (sigInfo == NULL || inInfo == NULL || outputInfo1 == NULL || outputInfo2 == NULL)
    {
        return -ERR_PARAM;
    }

    if (mod == 0)
        inputInfo = (vc_input_info *)inInfo;
    else
        filePath = (u8 *)inInfo;

    keyInfo = &sigInfo->keyInfo;

    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_ecc_key(keyInfo->keyID, &key,0);
    else
        res = vc_get_tmp_ecc_key(keyInfo->keyID, &key, 0);
    if (res != 0)
    {
        return -ERR_GET_KEY;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
    res = mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q);
    if(res != 0)
    {
        VC_LOG_E("do_ecdsa_verify mbedtls_ecp_check_pubkey error %d\n", res);
        goto exit;
    }

    mbedtls_ecp_group *grp = &(ec->grp);

    mbedtls_mpi r,s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_mpi_read_binary(&r, outputInfo1->data, outputInfo1->dataSize);
    mbedtls_mpi_read_binary(&s, outputInfo2->data, outputInfo2->dataSize);

    vc_hash_st hashInfo;
    hashInfo.hash_type = sigInfo->hash_type;
    if (mod == 0)
        res = vc_hash(&hashInfo, inputInfo, &hashout);
    else
        res = vc_hash_file(&hashInfo, filePath, &hashout);
    if (res != 0)
    {
        VC_LOG_E("ecc verify hash error %d\n",res);
        goto exit;
    }

    res = mbedtls_ecdsa_verify(grp, hashout.data, hashout.dataSize, &(ec->Q), &r, &s);

exit:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    mbedtls_pk_free(&key);

    return res;
}


s32 do_get_dhKey(vc_input_info *privInfo, vc_input_info *pubInfo , vc_output_info* outputInfo)
{
    s32 res = 0;
    mbedtls_mpi priv;
    mbedtls_ecp_point pub;

    mbedtls_mpi skey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group grp;

    if (privInfo == NULL || outputInfo == NULL || pubInfo == NULL)
    {
        return -ERR_PARAM;
    }

    mbedtls_mpi_init(&priv);
    mbedtls_mpi_init(&skey);
    mbedtls_ecp_point_init(&pub);
    mbedtls_ecp_group_init(&grp);

    res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (res != 0)
    {
        VC_LOG_E("do_get_dhKey mbedtls_ecp_group_load error %d\n", res);
        goto exit;
    }

    mbedtls_mpi_read_binary(&priv, privInfo->data, privInfo->dataSize);

    res = mbedtls_ecp_check_privkey(&grp, &priv);
    if(res != 0)
    {
        VC_LOG_E("do_get_dhKey mbedtls_ecp_check_privkey error %d\n", res);
        goto exit;
    }

    mbedtls_ecp_point_read_binary(&grp, &pub, pubInfo->data, pubInfo->dataSize);

    res = mbedtls_ecp_check_pubkey(&grp, &pub);
    if(res != 0)
    {
        VC_LOG_E("do_get_dhKey mbedtls_ecp_check_pubkey error %d\n", res);
        goto exit;
    }

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init(&ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *) "ecdhkey",
                               strlen("ecdhkey")
                                );

    if (res != 0)
    {
        VC_LOG_E("do_get_dhKey mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }


    res = mbedtls_ecdh_compute_shared(&grp, &skey,
                         &pub, &priv,
                         mbedtls_ctr_drbg_random, &ctr_drbg );
    if (res != 0)
    {
         VC_LOG_E("do_get_dhKey mbedtls_ecdh_compute_shared error %d\n", res);
        goto exit;
    }

    res = mbedtls_mpi_write_binary(&skey, outputInfo->data, outputInfo->dataSize);
    if (res != 0)
    {
        VC_LOG_E("do_get_dhKey mbedtls_mpi_write_binary error %d\n", res);
        goto exit;
    }
    vc_mov_data((vc_input_info *)outputInfo, mbedtls_mpi_size(&skey));


exit:
    mbedtls_mpi_free(&priv);
    mbedtls_mpi_free(&skey);
    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return res;
}

s32 vc_gen_ecdh_25519_key(vc_gen_key_info *genKeyInfo, vc_output_info *pubKey , vc_output_info *privKey)
{
    s32 res = 0;
    ecc_group_id id;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    if (genKeyInfo == NULL || privKey == NULL || pubKey == NULL)
    {
        return -ERR_PARAM;
    }

    id = ECP_DP_CURVE25519;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECKEY_DH;//MBEDTLS_PK_ECKEY_DH;//MBEDTLS_PK_ECDSA;

    mbedtls_pk_init(&key);
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(pk_alg));

    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_pk_setup error %d\n", res);
        goto exit;
    }

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *) "ecdsa",
                               strlen("ecdsa")
                                );

    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_ctr_drbg_seed error %d\n", res);
        goto exit;
    }

    res = mbedtls_ecp_gen_key(id,
                              mbedtls_pk_ec(key),
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg
                            );
    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_ecp_gen_key error %d\n", res);
        goto exit;
    }

    memset(pubKey->data, 0 ,pubKey->dataSize);

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);

    res = mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q);
    if(res != 0)
    {
        VC_LOG_E("mbedtls_ecp_check_pubkey error %d\n", res);
        goto exit;
    }

    res = mbedtls_ecp_check_privkey(&ec->grp, &ec->d);
    if(res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_ecp_check_privkey error %d\n", res);
        goto exit;
    }


    size_t olen;
    res = mbedtls_ecp_point_write_binary(&ec->grp, &ec->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                &olen, pubKey->data, pubKey->dataSize);
    pubKey->dataSize = olen;
    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_ecp_point_write_binary error %d\n", res);
        goto exit;
    }

    res = mbedtls_mpi_write_binary(&ec->d, privKey->data, privKey->dataSize);
    if (res != 0)
    {
        VC_LOG_E("vc_gen_ecdh_25519_key mbedtls_mpi_write_binary error %d\n", res);
        goto exit;
    }
    vc_mov_data((vc_input_info *)privKey, mbedtls_mpi_size(&ec->d));

exit:
    mbedtls_pk_free(&key);   //no func for free
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return res;
}


/*********************enc dec****************************/
static s32 vc_gen_prim(mbedtls_mpi *P)
{
    int ret = 0;
    uint8_t prime[32];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const uint8_t *pers = "CTR_DRBG";

    mbedtls_entropy_init(&entropy);//初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen(pers));
    if (ret != 0)
        goto cleanup;

    ret = mbedtls_mpi_gen_prime(P, sizeof(prime)*8, //生成素数长度
    1, //生成素数标志为1时(P-1)/2也为素数
                                mbedtls_ctr_drbg_random, //随机数生成接口
                                &ctr_drbg);//随机数结构体
    if (ret != 0)
        goto cleanup;
    mbedtls_mpi_write_binary(P, prime, sizeof(prime));

cleanup:
   // mbedtls_mpi_free(P); //释放大数结构体
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}

#if encodeECC
//欧拉准则 判断二次剩余，==1时，是p的二次剩余，即Y有解
static s32 vc_check_euler(mbedtls_mpi *x, mbedtls_ecp_keypair *ec, mbedtls_mpi *A)
{
    s32 res = 0;

    mbedtls_mpi mu3;  //x^3 ;; Amod
    mbedtls_mpi_init(&mu3);
    mbedtls_mpi_mul_mpi(&mu3, x, x);
    mbedtls_mpi_mul_mpi(&mu3, &mu3, x);

    mbedtls_mpi muax;
    mbedtls_mpi_init(&muax);
    mbedtls_mpi_mul_mpi(&muax, x, &ec->grp.A);

    mbedtls_mpi_add_mpi(&mu3, &mu3, &muax);
    mbedtls_mpi_add_mpi(&mu3, &mu3, &ec->grp.B);

    mbedtls_mpi_mod_mpi(A, &mu3, &ec->grp.P);        //A


    mbedtls_mpi i;
    mbedtls_mpi_init(&i);

    mbedtls_mpi_sub_int(&i, &ec->grp.P, (mbedtls_mpi_uint)1);
    mbedtls_mpi_div_int(&i, NULL, &i,(mbedtls_mpi_uint)2);

    mbedtls_mpi_exp_mod(&mu3, A, &i, &ec->grp.P , NULL);

    res = mbedtls_mpi_cmp_int(&mu3, (mbedtls_mpi_sint)1);

    mbedtls_mpi_free(&mu3);
    mbedtls_mpi_free(&muax);
    mbedtls_mpi_free(&i);

    return res;
}


//二次同余方程求解推论 （mod 8 == 1 需要其他算法支持，暂未实现）
static s32 vc_get_eccy(mbedtls_ecp_keypair *ec, mbedtls_mpi *A, mbedtls_mpi *y)
{
    s32 res = 0;
    mbedtls_mpi_uint mod4, mod8;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_mod_int(&mod4, &ec->grp.P, (mbedtls_mpi_uint)4);
    mbedtls_mpi_mod_int(&mod8, &ec->grp.P, (mbedtls_mpi_uint)8);
    if (mod4 == (mbedtls_mpi_uint)3 || mod8 == (mbedtls_mpi_uint)7)
    {
        mbedtls_mpi_add_int(&tmp, &ec->grp.P, (mbedtls_mpi_uint)1);
        mbedtls_mpi_div_int(&tmp, NULL, &tmp, (mbedtls_mpi_uint)4);
        mbedtls_mpi_exp_mod(y, A, &tmp, &ec->grp.P, NULL);
    }
    else if (mod4 == (mbedtls_mpi_uint)1 || mod8 == (mbedtls_mpi_uint)5)
    {
        mbedtls_mpi_add_int(&tmp, &ec->grp.P, (mbedtls_mpi_uint)3);
        mbedtls_mpi_div_int(&tmp, NULL, &tmp, (mbedtls_mpi_uint)8);
        mbedtls_mpi_exp_mod(y, A, &tmp, &ec->grp.P, NULL);
    }
    else if (mod8 == (mbedtls_mpi_uint)1)
    {
        VC_LOG_E("mod 8 = 1  not support\n");
        res = -1;
        goto exit;
    }
    else
    {
        VC_LOG_E("mod 1 :%lld, mod 2:%lld\n", mod4,mod8);
        res = -1;
        goto exit;
    }
exit:
    mbedtls_mpi_free(&tmp);
    return 0;
}


//for debug, check point on ecc
static s32 vc_dbg_checkXY(mbedtls_mpi *x, mbedtls_mpi *y, mbedtls_ecp_keypair *ec)
{
    s32 res = 0;

    mbedtls_mpi xx, yy, ax;
    mbedtls_mpi_init(&xx);
    mbedtls_mpi_init(&yy);
    mbedtls_mpi_init(&ax);

    mbedtls_mpi_mul_mpi(&xx, x, x);
    mbedtls_mpi_mul_mpi(&xx, &xx, x);  //x3

    mbedtls_mpi_mul_mpi(&ax, x, &ec->grp.A);  //ax

    mbedtls_mpi_add_mpi(&xx, &xx, &ax);
    mbedtls_mpi_add_mpi(&xx, &xx, &ec->grp.B);  //x3 + ax + b

    mbedtls_mpi_mod_mpi(&xx, &xx, &ec->grp.P);

    mbedtls_mpi_mul_mpi(&yy, y, y);
    mbedtls_mpi_mod_mpi(&yy, &yy, &ec->grp.P);

    res = mbedtls_mpi_cmp_mpi(&xx, &yy);

    mbedtls_mpi_free(&xx);
    mbedtls_mpi_free(&yy);
    mbedtls_mpi_free(&ax);
    return res;
}


//encode point to ecc
static s32 vc_p2ecc(mbedtls_mpi *plain, mbedtls_mpi *mk, mbedtls_ecp_point *point, mbedtls_ecp_keypair *ec)
{  //X = plain * MK + j  ,j = 0
    s32 res = 0;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    mbedtls_mpi mul;
    mbedtls_mpi_init(&mul);

    mbedtls_mpi A;
    mbedtls_mpi_init(&A);

    mbedtls_mpi j;
    mbedtls_mpi_init(&j);
    mbedtls_mpi_lset(&j ,(mbedtls_mpi_uint) 0);

    for (; mbedtls_mpi_cmp_mpi(mk, &j) > 0; mbedtls_mpi_add_int(&j, &j, (mbedtls_mpi_uint)7))
    {
        mbedtls_mpi_mul_mpi(&x, plain, mk);
        mbedtls_mpi_add_mpi(&x, &x, &j);

        ///////////// calc A
        res = vc_check_euler(&x, ec, &A);
        if (res != 0)
        {
            //VC_LOG_D("euler check not 1 ,-1\n");
        }
        else
            break;
    }
    mbedtls_mpi_free(&j);

    mbedtls_mpi y;
    mbedtls_mpi_init(&y);

    res = vc_get_eccy(ec, &A, &y);
    if (res != 0)
    {
        VC_LOG_E("get eccy error\n");
        goto exit;
    }

    //check
    #ifdef ECCDBG
    res = vc_dbg_checkXY(&x, &y, ec);
    printf("check 2222 %d\n", res);
    #endif

    mbedtls_mpi_copy(&point->X, &x);
    mbedtls_mpi_copy(&point->Y, &y);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&mul);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);
    return res;
}
#endif

//klen: 需要长度, v:hash长度
s32 vc_ec_kdf(HASH_ALG type ,vc_input_info *zInfo, u32 klen, vc_output_info *kInfo)  //sha256
{
    s32 res = 0;

    res = vc_kdf(type, zInfo, klen, kInfo);

    return res;
}

s32 do_ecc_enc(vc_ecc_encdec_info *     encInfo, vc_input_info *input, vc_output_info *output)
{
    s32 res = 0;
    vc_gen_key_info *keyInfo;
    u8 tmpStr[64] = {0};

    if (encInfo == NULL || input == NULL || output == NULL)
        return -ERR_PARAM;

    s32 outlen = (input->dataSize / 16 + 1) * 132;  // 1+64+1+64
    if (output->dataSize < outlen)
        return -ERR_NOT_ENOUGH;

    keyInfo = &encInfo->keyInfo;

    mbedtls_pk_context pubKey;
    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_ecc_key(keyInfo->keyID, &pubKey, 0);
    else
        res = vc_get_tmp_ecc_key(keyInfo->keyID, &pubKey, 0);
    if (res != 0)
    {
        return res;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pubKey);

    res = mbedtls_ecp_check_pubkey(&ec->grp, &ec->Q);
    if (res != 0)
    {
        VC_LOG_E("vc_ecc_enc mbedtls_ecp_check_pubkey error %d\n",res);
        goto exit;
    }

    mbedtls_ecp_point C1,C2;
    mbedtls_ecp_point_init(&C1);
    mbedtls_ecp_point_init(&C2);

    mbedtls_mpi rand;
    mbedtls_mpi_init(&rand);

    vc_gen_prim(&rand);
    if (res != 0)
    {
        goto exit;
    }
    mbedtls_mpi_mod_mpi(&rand, &rand, &ec->grp.N);

    res = mbedtls_ecp_mul(&ec->grp, &C1, &rand, &ec->grp.G, NULL, 0);
    if (res != 0)
    {
        VC_LOG_E("do_ecc_enc c1 mul error,res %d\n", res);
        goto exit;
    }

  /*  res = vc_dbg_checkXY(&C1.X, &C1.Y, ec);
    if (res != 0)
    {
        VC_LOG_E("vc_ecc enc c1 error \n");
        goto exit;
    }*/

    res = mbedtls_ecp_mul(&ec->grp, &C2, &rand, &ec->Q, NULL, 0);
    if (res != 0)
    {
        VC_LOG_E("do_ecc_enc c1 mul error,res %d\n", res);
        goto exit;
    }

    s32 offset = mbedtls_mpi_size(&C2.X);
    mbedtls_mpi_write_binary(&C2.X, output->data, offset);

    memcpy(&output->data[offset], input->data, input->dataSize);
    offset += input->dataSize;
    mbedtls_mpi_write_binary(&C2.Y, &output->data[offset], mbedtls_mpi_size(&C2.Y));

    offset += mbedtls_mpi_size(&C2.Y);



    s32 orilen = output->dataSize;
    output->dataSize = offset;

    vc_output_info hashdata;
    hashdata.data = tmpStr;
    hashdata.dataSize = sizeof(tmpStr);

    vc_hash_st hashInfo;
    hashInfo.hash_type = encInfo->hash_type;

    res = vc_hash(&hashInfo, (vc_input_info *)output, &hashdata);             //s3
    if (res != 0)
    {
        VC_LOG_E("do_ecc_enc vc_hash error,res %d\n", res);
        goto exit;
    }
    output->dataSize = orilen;

    size_t c1len, c2len;
    offset = 0;
    mbedtls_ecp_point_write_binary(&ec->grp, &C1, MBEDTLS_ECP_PF_UNCOMPRESSED, &c1len, output->data, output->dataSize);       //s1
    offset += c1len;

    vc_output_info tmpc2;
    u8 c2buf[POINT_BUF_MAX] = {0};
    tmpc2.data = c2buf;
    tmpc2.dataSize = POINT_BUF_MAX;
    mbedtls_ecp_point_write_binary(&ec->grp, &C2, MBEDTLS_ECP_PF_UNCOMPRESSED, &c2len, tmpc2.data, tmpc2.dataSize);

    tmpc2.data = &c2buf[1];
    tmpc2.dataSize = c2len;

    vc_output_info tmpout;
    tmpout.data = &output->data[offset];
    tmpout.dataSize -= c1len;

    res = vc_ec_kdf(encInfo->hash_type, (vc_input_info *)&tmpc2, input->dataSize * 8, &tmpout);
    if (res != 0)
    {
        VC_LOG_E("do_ecc_enc vc_ec_kdf,res %d\n", res);
        goto exit;
    }

    vc_or_data(input, &tmpout);                  //s2
    offset += input->dataSize;

    memcpy(&output->data[offset], hashdata.data, hashdata.dataSize);
    offset += hashdata.dataSize;
    output->dataSize = offset;

exit:
    mbedtls_mpi_free(&rand);
    mbedtls_ecp_point_free(&C1);
    mbedtls_ecp_point_free(&C2);
    mbedtls_pk_free(&pubKey);
    return res;
}

static s32 vc_data2out(u8 *data, u8 *outputbuf)
{
    s32 i = 0;
    for (i = 0; i < TMPOUTLEN; i++)
    {
        if (data[i] == DATAFLAG)
        {
            break;
        }
    }

    memcpy(outputbuf, &data[i+1], TMPOUTLEN - i - 1);

    return TMPOUTLEN - i - 1;
}

s32 do_ecc_dec(vc_ecc_encdec_info* encInfo, vc_input_info *input, vc_output_info *output)
{
    s32 res = 0;
    vc_gen_key_info *keyInfo;

    if (encInfo == NULL || input == NULL || output == NULL)
        return -ERR_PARAM;

    keyInfo = &encInfo->keyInfo;

    mbedtls_pk_context privKey;
    if (keyInfo->keyID <= MAX_KEY_ID)
        res = vc_get_ecc_key(keyInfo->keyID, &privKey, 1);
    else
        res = vc_get_tmp_ecc_key(keyInfo->keyID, &privKey, 1);
    if (res != 0)
    {
        return res;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(privKey);

    res = mbedtls_ecp_check_privkey(&ec->grp, &ec->d);
    if (res != 0)
    {
        VC_LOG_E("vc_ecc_dec mbedtls_ecp_check_privkey %d\n", res);
        goto exit;
    }

    mbedtls_ecp_point C1,C2;
    mbedtls_ecp_point_init(&C1);
    mbedtls_ecp_point_init(&C2);


    s32 cc1len, cc2len ,cc3len;
    cc1len = (ec->grp.pbits / 8 + (ec->grp.pbits % 8 == 0 ? 0 : 1))*2+1;  //65;//input->data[0] + 1;  2L+1

    cc3len = vc_hash_len(encInfo->hash_type);     /////////////////////////////////sha256
    cc2len = input->dataSize - cc1len - cc3len;

    mbedtls_ecp_point_read_binary(&ec->grp, &C1, input->data, cc1len);
   /* res = vc_dbg_checkXY(&C1.X, &C1.Y, ec);
    if (res != 0)
    {
        VC_LOG_E("vc_ecc_dec c1 error \n");
        goto exit;
    }*/

    mbedtls_ecp_mul(&ec->grp, &C2, &ec->d, &C1, NULL, 0);

    size_t c2len;

    vc_output_info tmpc2;
    u8 c2buf[POINT_BUF_MAX] = {0};
    tmpc2.data = c2buf;
    tmpc2.dataSize = POINT_BUF_MAX;
    mbedtls_ecp_point_write_binary(&ec->grp, &C2, MBEDTLS_ECP_PF_UNCOMPRESSED, &c2len, tmpc2.data, tmpc2.dataSize);

    tmpc2.data = &c2buf[1];
    tmpc2.dataSize = c2len;

    res = vc_ec_kdf(encInfo->hash_type, (vc_input_info *)&tmpc2, cc2len * 8, output);
    if (res != 0)
    {
        VC_LOG_E("do_ecc_enc vc_ec_kdf,res %d\n", res);
        goto exit;
    }

    vc_input_info tmpin;
    tmpin.data = &input->data[cc1len];
    tmpin.dataSize = cc2len;

    vc_or_data(&tmpin, output);                  //s2

exit:
    mbedtls_ecp_point_free(&C1);
    mbedtls_ecp_point_free(&C2);
    mbedtls_pk_free(&privKey);
    return res;
}

