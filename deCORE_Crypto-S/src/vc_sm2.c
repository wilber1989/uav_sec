#ifdef SMENABLE

#include "../include/vc_sm2.h"
#include "../include/vc_sw_crypt.h"
#include "../include/openssl/sm2.h"
#include "../include/openssl/crypto.h"
#include "../include/internal/evp_int.h"
#include "../include/ec/ec_lcl.h"
#include "../include/bn/bn_lcl.h"
#include "../include/vc_key.h"

//sm2 ,256
s32 vc_gen_gm_key(vc_gen_key_info *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey)
{
    s32 ret = 0;

	BN_CTX *ctx = NULL;
	BIGNUM *bn_d = NULL, *bn_x = NULL, *bn_y = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	EC_POINT *ec_pt = NULL;
	unsigned char pub_key_x[32], pub_key_y[32];

	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	if ( !(bn_y) )
	{
	   goto clean_up;
	}

	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1)) )
	{
	   goto clean_up;
	}
	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
	   goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
	   goto clean_up;
	}

	do
	{
	   if ( !(BN_rand_range(bn_d, bn_order)) )
	   {
	      goto clean_up;
	   }
	} while ( BN_is_zero(bn_d) );

	if ( !(EC_POINT_mul(group, ec_pt, bn_d, NULL, NULL, ctx)) )
	{
	   goto clean_up;
	}
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt,
						   bn_x,
						   bn_y,
						   ctx)) )
	{
	   goto clean_up;
	}

    privKey->dataSize = 32;
    memset(privKey->data, 0, privKey->dataSize);
	if ( BN_bn2binpad(bn_d,
	                  privKey->data,
			  privKey->dataSize) !=  privKey->dataSize)
	{
	   goto clean_up;
	}

	if ( BN_bn2binpad(bn_x,
	                  pub_key_x,
			  sizeof(pub_key_x)) != sizeof(pub_key_x) )
	{
	   goto clean_up;
	}
	if ( BN_bn2binpad(bn_y,
	                  pub_key_y,
			  sizeof(pub_key_y)) != sizeof(pub_key_y) )
	{
	   goto clean_up;
	}

    memset(pubKey->data, 0, pubKey->dataSize);
	pubKey->data[0] = 0x4;
	memcpy((pubKey->data + 1), pub_key_x, sizeof(pub_key_x));
	memcpy((pubKey->data + 1 + sizeof(pub_key_x)), pub_key_y, sizeof(pub_key_y));
    pubKey->dataSize = 65;

clean_up:
    if (ctx)
	{
	   BN_CTX_end(ctx);
	   BN_CTX_free(ctx);
	}

	if (group)
	{
	   EC_GROUP_free(group);
	}

	if (ec_pt)
	{
	   EC_POINT_free(ec_pt);
	}

	return ret;

#ifdef my_ori
    EC_KEY *keypair = NULL;
    EC_GROUP *group1 = NULL;
    size_t pri_len;
    size_t pub_len;
    u8 *pub_key = pubKey->data;
    u8 *pri_key = privKey->data;

    keypair = EC_KEY_new();
    if(!keypair) {
        VC_LOG_E("vc_gen_gm_key failed EC_KEY_new \n");
        return -ERR_PARAM;
    }

    group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if(group1 == NULL)
    {
        VC_LOG_E("vc_gen_gm_key failed EC_GROUP_new_by_curve_name \n");
        return -ERR_PARAM;
    }

    ret = EC_KEY_set_group(keypair, group1);
    if(ret != 1)
    {
        VC_LOG_E("vc_gen_gm_key failed EC_KEY_set_group %d\n", ret);
        return -ERR_PARAM;
    }

    ret = EC_KEY_generate_key(keypair);
    if(ret != 1)
    {
        VC_LOG_E("vc_gen_gm_key failed EC_KEY_generate_key %d\n", ret);
        return -ERR_PARAM;
    }
    ret = 0;

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_ECPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, keypair);

    privKey->dataSize = BIO_pending(pri);
    pubKey->dataSize = BIO_pending(pub);

    BIO_read(pri, pri_key, privKey->dataSize);
    BIO_read(pub, pub_key, pubKey->dataSize);

    pri_key[privKey->dataSize] = '\0';
    pub_key[pubKey->dataSize] = '\0';

clean:
    EC_KEY_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
#endif
    return ret;
}

static s32 buf2hex(u8 *buf, s32 lbuf, u8 *hex, s32 lhex)
{
    s32 res = 0;

    s32 i;
    if (lbuf * 2 > lhex)
    {
        VC_LOG_E("buf2hex error\n");
        return -ERR_NOT_ENOUGH;
    }

    for (i = 0; i < lbuf; i++)
    {
        u8 a0 = buf[i] % (u8)16;
        if (a0 <= 9)
            hex[i*2 + 1] = a0 + '0';
        else
            hex[i*2 + 1] = a0 - 10 + 'a';

        u8 a1 = buf[i] / (u8)16;
        if (a1 <= 9)
            hex[i*2] = a1 + '0';
        else
            hex[i*2] = a1 - 10 + 'a';
    }

    return res;
}

s32 vc_get_sm2_key(u32 keyid, EC_KEY * keyInfo, s32 mod)
{
    s32 res = 0;
    FILE *fp = NULL;
    u32 buflen;
    u8 *tmpStr;
    vc_key_type keyType;
    vc_output_info outKey;
    u8 tmpStr2[128];

    BIO *pri = NULL;//= BIO_new(BIO_s_mem());
    BIO *pub = NULL;//= BIO_new(BIO_s_mem());

    const EC_GROUP *group = NULL;
    EC_POINT *pub_key = NULL;
    BIGNUM *priv_key = NULL;

    res = vc_set_keybit();
    if (res != 0)
    {
        VC_LOG_E("open dir error %d\n", res);
        return -ERR_PARAM;
    }

    sprintf(tmpStr2, "%s/KEY_%d", KEY_FILE_PATH, keyid);

    buflen = MAX_SM2_KEY; //key文件数据部分大小
    tmpStr = (u8 *)malloc(buflen);
    if (tmpStr == NULL)
    {
        return -ERR_MALLOC;
    }

    fp = fopen(tmpStr2, "rb");
    if (fp == NULL)
    {
        VC_LOG_E("vc_get_sm2_key open file error\n");
        res = -ERR_PARAM; //打开文件失败
        goto exit;
    }

    res = vc_check_keymac(fp, NULL);

    keyType = vc_get_key_type(fp);

    if ((mod == 0 && keyType != KEY_TYPE_SM2_PUB)
        || (mod == 1 && keyType != KEY_TYPE_SM2_PRIV))
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
    outKey.data[outKey.dataSize] = 0;

    u8 hex[MAX_SM2_KEY] = {0};
    res = buf2hex(outKey.data, outKey.dataSize, hex, MAX_SM2_KEY);

    if (mod == 0)
    {/*
        pub = BIO_new(BIO_s_mem());
        res = BIO_write(pub, outKey.data, outKey.dataSize);

        PEM_read_bio_EC_PUBKEY(pub, keyInfo, NULL, 0);

        BIO *bio_err = NULL;
        printf("pppppkkkkkk\n");
        BIGNUM *x = (*keyInfo)->pub_key->X;
        BIGNUM *y = (*keyInfo)->pub_key->Y;
        char *xx = BN_bn2hex(x);
        printf("x is %s\n", xx);
        char *yy = BN_bn2hex(y);
        printf("y is %s\n", yy);*/

        group = EC_KEY_get0_group(keyInfo);
        pub_key = EC_POINT_new(group);

        pub_key = EC_POINT_hex2point(group, hex, pub_key, NULL);
        if (pub_key == NULL)
        {
            VC_LOG_E("vc_get_sm2_key EC_POINT_hex2point error %d\n", res);
            if (res == 0)
                res = -ERR_KEY_READ;
            goto exit;
        }

        res = EC_KEY_set_public_key(keyInfo, pub_key);
        if (res != 1)
        {
            VC_LOG_E("vc_get_sm2_key EC_KEY_set_public_key error %d\n", res);
            if (res == 0)
                res = -ERR_KEY_READ;
            goto exit;
        }

        if (keyInfo != NULL)
            res = 0;
        else
            res = -1;
    }
    else
    {
       /* pri = BIO_new(BIO_s_mem());
        res = BIO_write(pri, outKey.data, outKey.dataSize);

        *keyInfo = PEM_read_bio_ECPrivateKey(pri, keyInfo, NULL, NULL);*/

        res = BN_hex2bn(&priv_key, hex);
        if (res == 0)
        {
            VC_LOG_E("vc_get_sm2_key BN_hex2bn error %d\n", res);
            if (res == 0)
                res = -ERR_KEY_READ;
            goto exit;
        }

        res = EC_KEY_set_private_key(keyInfo, priv_key);
        if (res != 1)
        {
            VC_LOG_E("vc_get_sm2_key EC_KEY_set_private_key error %d\n", res);
            if (res == 0)
                res = -ERR_KEY_READ;
            goto exit;
        }

        if (keyInfo != NULL)
            res = 0;
        else
            res = -1;
    }

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

    if (group != NULL)
    {
        EC_GROUP_free(group);
    }

    if (pub_key != NULL)
    {
        EC_POINT_free(pub_key);
    }

    if (priv_key != NULL)
    {
        BN_free(priv_key);
    }

 //   BIO_free_all(pub);
  //  BIO_free_all(pri);
    return res;
}

s32 vc_get_sm2_key_str(u32 keyid, u8 * keyInfo, s32 mod)
{
    s32 res = 0;
    FILE *fp = NULL;
    u32 buflen = 0;
    u8 *tmpStr = NULL;
    vc_key_type keyType = {0x00};
    vc_output_info outKey = {0x00};
    u8 tmpStr2[128] = {0x00};

    if (keyid <= MAX_KEY_ID)
    {
        res = vc_set_keybit();
        if (res != 0)
        {
            VC_LOG_E("open dir error %d\n", res);
            return -ERR_PARAM;
        }

        sprintf(tmpStr2, "%s/KEY_%d", KEY_FILE_PATH, keyid);

        buflen = MAX_SM2_KEY; //key文件数据部分大小
        tmpStr = (u8 *)malloc(buflen);
        if (tmpStr == NULL)
        {
            return -ERR_MALLOC;
        }

        fp = fopen(tmpStr2, "rb");
        if (fp == NULL)
        {
            VC_LOG_E("vc_get_sm2_key open file error\n");
            res = -ERR_PARAM; //打开文件失败
            goto exit;
        }

        res = vc_check_keymac(fp, NULL);

        keyType = vc_get_key_type(fp);

        if ((mod == 0 && keyType != KEY_TYPE_SM2_PUB)
            || (mod == 1 && keyType != KEY_TYPE_SM2_PRIV))
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
        outKey.data[outKey.dataSize] = 0;
        {
            int i = 0;
            printf("public key ------------------ \n");
            for(i=0;i<outKey.dataSize;i++)
                printf("%02x",outKey.data[i]);
            printf("\n");
        }
    }
    else
    {

        keyType = vc_get_tmp_key_type(keyid);
        if ((mod == 0 && keyType != KEY_TYPE_SM2_PUB)
            || (mod == 1 && keyType != KEY_TYPE_SM2_PRIV))
        {
            res = -ERR_KEY_TYPE; //key类型错误
            goto exit;
        }
        buflen = MAX_SM2_KEY; //key文件数据部分大小
        tmpStr = (u8 *)malloc(buflen);
        if (tmpStr == NULL)
        {
            return -ERR_MALLOC;
        }
        outKey.data = tmpStr;
        outKey.dataSize = buflen;
        memset(tmpStr, 0, buflen);
        res = vc_get_tmp_key_data(keyid, &outKey);
        if (res != 0)
        {
            res = -ERR_KEY_READ; //key读取错误
            goto exit;
        }
    }

    //u8 hex[MAX_SM2_KEY] = {0};
    res = buf2hex(outKey.data, outKey.dataSize, keyInfo, MAX_SM2_KEY);
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

__attribute__ ((visibility("default")))
s32 vc_sm2_get_compress(vc_input_info *before , vc_output_info *output)
{
    if (before->dataSize != 65)
    {
        VC_LOG_E("sm2 pub key must be 65\n");
        return -1;
    }

    if (output->dataSize < 33)
    {
        VC_LOG_E("output buffer not enough");
        return -ERR_NOT_ENOUGH;
    }

    if (before->data[0] != 0x04)
    {
        VC_LOG_E("sm2 pub key not compressed\n");
        return -1;
    }

    u8 ypLast = before->data[64] & 0x01;

    if (ypLast == 0)
        output->data[0] = 0x02;
    else
        output->data[0] = 0x03;

    memcpy(&output->data[1], &before->data[1] , 32);
    output->dataSize = 33;

    return 0;
}

__attribute__ ((visibility("default")))
s32 vc_sm2_get_decompress(vc_input_info *before, vc_output_info *output)
{
    s32 res = 0;

    if (before == NULL || output == NULL || before->data == NULL || output->data == NULL)
        return -ERR_PARAM;

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    EC_POINT *p = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;

    p = EC_POINT_new(group);
    if (p == NULL)
    {
        VC_LOG_E("new point error\n");
        res = -ERR_ALG_PROCESS;
        goto exit;
    }

    int yflag = before->data[0];
    if (yflag == 0x02)
        yflag = 0;
    else if (yflag == 0x03)
        yflag = 1;

    x = BN_new();
    BN_bin2bn(&before->data[1], 32, x);
    if (x == NULL)
    {
        res = -ERR_ALG_PROCESS;
        goto exit;
    }

    ctx = BN_CTX_new();

    res = EC_POINT_set_compressed_coordinates_GFp(group, p, x, yflag, ctx);
    if (res != 1)
    {
        VC_LOG_E("EC_POINT_set_compressed_coordinates_GFp point error\n");
        res = -ERR_ALG_PROCESS;
        goto exit;
    }

    y = BN_new();
    res = EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
    if (res != 1)
    {
        VC_LOG_E("EC_POINT_get_affine_coordinates_GFp point error\n");
        res = -ERR_ALG_PROCESS;
        goto exit;
    }

    if (res == 1)
    {
        res = 0;

        output->data[0] = 0x04;
        memcpy(&(output->data[1]), &(before->data[1]), 32);
        output->dataSize = 33;
    }

    output->dataSize += BN_bn2bin(y, &(output->data[33]));

exit:
    EC_GROUP_free(group);
    EC_POINT_free(p);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);

    return res;
}

EC_KEY *new_ec_key(const EC_GROUP *group,
                          const char *sk, const char *xP, const char *yP)
{
    int ok = 0;
    EC_KEY *ec_key = NULL;
    BIGNUM *d = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    OPENSSL_assert(group);
    OPENSSL_assert(xP);
    OPENSSL_assert(yP);

    if (!(ec_key = EC_KEY_new())) {
        goto end;
    }
    if (!EC_KEY_set_group(ec_key, group)) {
        goto end;
    }

    if (sk) {
        if (!BN_hex2bn(&d, sk)) {
            goto end;
        }
        if (!EC_KEY_set_private_key(ec_key, d)) {
            goto end;
        }
    }

    if (xP && yP) {
        if (!BN_hex2bn(&x, xP)) {
            goto end;
        }
        if (!BN_hex2bn(&y, yP)) {
            goto end;
        }
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
            goto end;
        }
    }

    ok = 1;
end:
    if (d) BN_free(d);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (!ok && ec_key) {
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}

s32 do_sm2_enc(vc_sm2_encdec_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 ret = 0;
    EC_KEY *ec_key = NULL;
    vc_gen_key_info *keyInfo;

    if (encInfo == NULL || inputInfo == NULL || outputInfo == NULL)
        return -ERR_PARAM;

    keyInfo = &encInfo->keyInfo;

    EC_GROUP *group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if(group1 == NULL)
    {
        VC_LOG_E("do_sm2_verify failed EC_GROUP_new_by_curve_name \n");
        ret = -ERR_PARAM;
        goto exit;
    }

    u8 xy[131] = {0};
    u8 xp[65] = {0};
    u8 yp[65] = {0};
    ret = vc_get_sm2_key_str(keyInfo->keyID, xy, 0);
    if (ret != 0)
    {
        VC_LOG_E("do_sm2_verify failed vc_get_sm2_key_str pub  %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }
    memcpy(xp, &xy[2], 64);
    memcpy(yp, &xy[64+2], 64);

    ec_key = new_ec_key(group1, NULL, xp, yp);
    if (ec_key == NULL)
    {
        VC_LOG_E("do_sm2_verify failed new_ec_key %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }

    ret = SM2_encrypt(NID_sm3, inputInfo->data, inputInfo->dataSize,
        outputInfo->data, (size_t *)&(outputInfo->dataSize) , ec_key);
    if (ret != 1)
    {
        VC_LOG_E("vc_sm2_enc SM2_do_encrypt error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }
    else
        ret = 0;

exit:
    EC_GROUP_free(group1);
    EC_KEY_free(ec_key);
    return ret;
}


s32 do_sm2_dec(vc_sm2_encdec_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 ret = 0;
    EC_KEY *pri_key = NULL;

    vc_gen_key_info *keyInfo;

    if (encInfo == NULL || inputInfo == NULL || outputInfo == NULL)
        return -ERR_PARAM;

    keyInfo = &encInfo->keyInfo;

    pri_key = EC_KEY_new();
    if(!(pri_key)) {
        VC_LOG_E("vc_sm2_dec failed EC_KEY_new \n");
        ret =  -ERR_PARAM;
        goto exit;
    }

    EC_GROUP *group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if(group1 == NULL)
    {
        VC_LOG_E("vc_sm2_dec failed EC_GROUP_new_by_curve_name \n");
        ret =  -ERR_PARAM;
        goto exit;
    }

    ret = EC_KEY_set_group(pri_key, group1);
    if(ret != 1)
    {
        VC_LOG_E("vc_sm2_dec failed EC_KEY_set_group %d\n", ret);
        ret =  -ERR_PARAM;
        goto exit;
    }

    ret = vc_get_sm2_key(keyInfo->keyID, pri_key, 1);
    if (ret != 0)
    {
        VC_LOG_E("vc_sm2_dec vc_get_sm2_key error %d\n", ret);
        goto exit;
    }

    ret = SM2_decrypt(NID_sm3, inputInfo->data, inputInfo->dataSize,
        outputInfo->data, (size_t *)&(outputInfo->dataSize) , pri_key);
    if (ret != 1)
    {
        VC_LOG_E("vc_sm2_dec SM2_decrypt error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }
    else
        ret = 0;

exit:
    EC_KEY_free(pri_key);
    EC_GROUP_free(group1);
    return ret;
}

s32 do_sm2_sign(vc_sm2_sigver_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 ret = 0;
    EC_KEY *ec_key = NULL;
    vc_gen_key_info *keyInfo;
    vc_gen_key_info *skeyInfo;

    if (encInfo == NULL || inputInfo == NULL || outputInfo == NULL)
        return -ERR_PARAM;

    keyInfo = &encInfo->keyInfo;
    skeyInfo = &encInfo->skeyInfo;

    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();
    const char *id = encInfo->id;

    EC_GROUP *group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if(group1 == NULL)
    {
        VC_LOG_E("vc_sm2_sign failed EC_GROUP_new_by_curve_name \n");
        ret = -ERR_PARAM;
        goto exit;
    }

    u8 sk[65] = {0};
    u8 xy[131] = {0};
    u8 xp[65] = {0};
    u8 yp[65] = {0};
    ret = vc_get_sm2_key_str(keyInfo->keyID, xy, 0);
    if (ret != 0)
    {
        VC_LOG_E("vc_sm2_sign failed vc_get_sm2_key_str pub  %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }
    memcpy(xp, &xy[2], 64);
    memcpy(yp, &xy[64+2], 64);

    ret = vc_get_sm2_key_str(skeyInfo->keyID, sk, 1);
    if (ret != 0)
    {
        VC_LOG_E("vc_sm2_sign failed vc_get_sm2_key_str priv %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }

    ec_key = new_ec_key(group1, sk, xp, yp);
    if (ec_key == NULL)
    {
        VC_LOG_E("vc_sm2_sign failed new_ec_key %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }

    unsigned char dgst[64];
    size_t dgstlen;
    dgstlen = sizeof(dgst);
    ret = SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key);
    if (ret != 1)
    {
        VC_LOG_E("vc_sm2_sign SM2_compute_id_digest error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }

    dgstlen = sizeof(dgst);
    ret = SM2_compute_message_digest(id_md, msg_md,
        (const unsigned char *)inputInfo->data, inputInfo->dataSize, id, strlen(id),
        dgst, &dgstlen, ec_key);
    if (ret != 1)
    {
        VC_LOG_E("vc_sm2_sign SM2_compute_message_digest error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }

    ret = SM2_sign(NID_undef, dgst, dgstlen,
        outputInfo->data, &(outputInfo->dataSize) , ec_key);
    if (ret != 1)
    {
        VC_LOG_E("vc_sm2_sign SM2_sign error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }
    else
        ret = 0;

exit:
    EC_GROUP_free(group1);
    EC_KEY_free(ec_key);
    return ret;
}

s32 do_sm2_verify(vc_sm2_sigver_info *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo)
{
    s32 ret = 0;
    EC_KEY *ec_key = NULL;
    vc_gen_key_info *keyInfo;

    if (encInfo == NULL || inputInfo == NULL || outputInfo == NULL)
        return -ERR_PARAM;

    keyInfo = &encInfo->keyInfo;

    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();
    const char *id = encInfo->id;

    EC_GROUP *group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if(group1 == NULL)
    {
        VC_LOG_E("do_sm2_verify failed EC_GROUP_new_by_curve_name \n");
        ret = -ERR_PARAM;
        goto exit;
    }

    u8 xy[131] = {0};
    u8 xp[65] = {0};
    u8 yp[65] = {0};
    ret = vc_get_sm2_key_str(keyInfo->keyID, xy, 0);
    if (ret != 0)
    {
        VC_LOG_E("do_sm2_verify failed vc_get_sm2_key_str pub  %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }
    memcpy(xp, &xy[2], 64);
    memcpy(yp, &xy[64+2], 64);

    ec_key = new_ec_key(group1, NULL, xp, yp);
    if (ec_key == NULL)
    {
        VC_LOG_E("do_sm2_verify failed new_ec_key %d\n", ret);
        ret = -ERR_GET_KEY;
        goto exit;
    }

    unsigned char dgst[64];
    size_t dgstlen;
    dgstlen = sizeof(dgst);
    ret = SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key);
    if (ret != 1)
    {
        VC_LOG_E("do_sm2_verify SM2_compute_id_digest error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }

    dgstlen = sizeof(dgst);
    ret = SM2_compute_message_digest(id_md, msg_md,
        (const unsigned char *)inputInfo->data, inputInfo->dataSize, id, strlen(id),
        dgst, &dgstlen, ec_key);
    if (ret != 1)
    {
        VC_LOG_E("do_sm2_verify SM2_compute_message_digest error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }

    ret = SM2_verify(NID_undef, dgst, dgstlen,
        outputInfo->data, (outputInfo->dataSize) , ec_key);
    if (ret != 1)
    {
        VC_LOG_E("do_sm2_verify SM2_verify error, %d\n", ret);
        ret = -ERR_ALG_PROCESS;
        goto exit;
    }
    else
        ret = 0;

exit:
    EC_GROUP_free(group1);
    EC_KEY_free(ec_key);
    return ret;
}

#endif
