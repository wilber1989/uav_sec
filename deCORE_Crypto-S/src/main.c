#include "../include/vc_sw_crypt_service.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

static s32 costflag = 0;
static s32 costcount = 0;

/*********TEST DATA************/
#define TST_AES_KEY_ID_1 (0x01)
static unsigned char tst_iv[16] = {0};
static unsigned char tst_key[16] = {0x00, 0x01,0x00, 0x01,0x00, 0x01,0x00, 0x01,
                                    0x00, 0x01,0x00, 0x01,0x00, 0x01,0x00, 0x01};
static unsigned char tst_enc_data[32] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x9,0x8,
                                         0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x1,0x2,0x3,0x4,
                                         0x5,0x6,0x7,0x8,0x9,0x9,0x8,0x7,0x6,0x5};
//static unsigned char tst_enc_data[32] = "qewrtyuiasdfghjhqewrtyuiasdfghjh";
static unsigned char tst_dec_data[32] = {0x3b,0x9a,0xa6,0x87,0x83,0x5c,0xfc,0x8c,0x60,
                                         0x12,0xc2,0xaa,0xea,0xf8,0xf2,0x2e,0xba,0x94,0x9e,
                                         0x8d,0x49,0x02,0xe6,0x65,0x76,0x3b,0xb0,0x0e,0x1a,
                                         0xc1,0xbf,0xa3};

#if 0
static unsigned char tst_enc_data2[32] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x9,0x8,
                                         0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x1,0x2,0x3,0x4,
                                         0x5,0x6,0x7,0x8};
static unsigned char tst_dec_data2[32] = {0x3b,0x9a,0xa6,0x87,0x83,0x5c,0xfc,0x8c,0x60,0x12,
    0xc2,0xaa,0xea,0xf8,0xf2,0x2e,0x2e,0xe7,
    0x3b,0xc2,0x1b,0x3b,0xee,0x52,0xfd,0x4f,0xcb,0xa0,0xb3,0x3d,0xf0,0x5b};
                                         #else
static unsigned char tst_enc_data2[32] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0x9,0x8,
                                         0x7,0x6,0x5,0x4,0x3,0x2,0xfa,0xcc};
static unsigned char tst_dec_data2[32] = {0x3b,0x9a,0xa6,0x87,0x83,0x5c,0xfc,0x8c,0x60,0x12,0xc2,
    0xaa,0xea,0xf8,0xf2,0x2e,0xfa,0x3a,0x3f,0x20,0x6e,0x1f,0x39,0xa6,0x8e,0x3d,0x86,0x09,0xa7,0x81,0x7e,0x48};
#endif
static unsigned char tst_enc_data2_1[16] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                            0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1};


static unsigned char tst_enc_data3[67] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,
                                          0xaa,0xbb,0xcc};


static unsigned char tst_enc_gcm_add[21] = {0xaa,0xbb,0xcc,0xdd,0xee,0xf1,0xf2,
0xaa,0xbb,0xcc,0xdd,0xee,0xf1,0xf2,
0xaa,0xbb,0xcc,0xdd,0xee,0xf1,0xf2};


static unsigned char tst_dec_data3[256] = {0x0c,0x48,0x24,0xf1,0xca,0x5c,0xbf,0x07,0xe8,0x4d,0xc0,
    0x9c,0x71,0x59,0xe0,0x93,0xb1,0x42,0x52,0x1c,0xa2,
    0x4a,0xfc,0x74,0xe9,0x74,0xf6,0xa3,0x60,0x5a,0x6e,
    0x31,0x89,0x2c,0xec,0x96,0x13,0x41,0x7e,0x03,0xe6,
    0xb2,0x37,0x8a,0x8a,0xc1,0xa6,0xc6,0x90,0xd4,0x47,
    0x8f,0x02,0xaf,0x62,0x5b,0xf4,0x34,0x61,0x05,0xde,
    0x8c,0xd4,0xef,0x9d,0x70,0x61,0x5d,0x9a,0x0f,0x0e,
    0x7b,0xfe,0x1f,0x85,0x3c,0x1f,0xe5,0x2b,0x06,0xf2,
    0x5a,0x5a,0x87,0xc5,0x9a,0x6a,0x2b,0xa2,0x72,0x75,
    0x4c,0x5e,0x7f,0xda,0x3b,0x14,0xe1,0xa9,0xe4,0x1a,
    0x60,0xa9,0x7c,0x2a,0x94,0x0c,0xcd,0x79,0x91,0x19,
    0x22,0x98,0x32,0xd0,0xc2,0xa8,0x07,0xc3,0x17,0x2c,
    0xf6,0x03,0x6d,0x02,0xe4,0x58,0x70,0x5d,0x6d,0x78,
    0x87,0xd9,0xdb,0xd1,0xc7,0xc6,0x92,0xf7,0x09,0x4c,
    0xf2,0x9b,0x51,0x4c,0xdf,0xd1,0xb5,0x1d,0xa2,0xa5,
    0xf6,0x25,0xe2,0x33,0x0b,0x37,0x70,0x2c,0x55,0xec,
    0xea,0x63,0x53,0xd6,0x08,0x10,0x89,0xb9,0x2c,0xde,
    0xc9,0xe6,0x49,0x6a,0x3f,0x2e,0x6b,0xda,0xb5,0x9c,
    0x8c,0x53,0x71,0xf4,0x97,0xce,0xb8,0xb8,0xac,0xe7,
    0xc9,0x29,0xe7,0x0c,0x0e,0xc5,0x3c,0x2b,0x81,0xbf,
    0xf6,0x24,0x63,0xc5,0x02,0x8b,0x6b,0x18,0xe9,0x83,
    0x4a,0x14,0x3c,0x52,0xc2,0xde,0x04,0xff,0xe7,0x0f,
    0xfc,0x04,0x3c,0x7b,0x71,0x1c,0x79,0xf5,0xf5,0xf6,
    0xa2,0x00,0x36,0x81,0x67,0x70,0x2e,0x56,0x76,0x4c,
    0xc3,0x11,0x76,0xaa,0x8f,0x6a,0xf1,0xe2,0x8b,0xce,
    0x87,0xd9,0xc1,0xf1,0x7f};

static unsigned char tst_verify_data[256] = {0x99,0xd9,0xd3,0x72,0x4b,0xeb,0xfa,0x1e,0x10,0xd1,
    0xb6,0x05,0x8b,0x11,0x6e,0x6b,0xae,0x9f,0x56,0x23,0xfa,0xd7,0xaf,0x79,0xee,0xf5,0xc2,0xc3,
    0x20,0x3c,0x8a,0x75,0xed,0xfc,0x58,0x7a,0x9d,0x69,0x0f,0xbf,0xfc,0x51,0x3f,0xec,0x0a,0xbf,
    0x38,0x0e,0x11,0xa9,0xeb,0x8f,0x26,0xd7,0x7f,0xd2,0x00,0x3e,0xdd,0xa4,0x06,0x06,0x4b,0xb7,
    0x3b,0x96,0x52,0x5f,0xf6,0xe2,0x74,0xc1,0x0f,0xc3,0x39,0x72,0x47,0x7b,0x6b,0x40,0x2d,0xd2,
    0xfe,0x2a,0x33,0xa0,0x34,0x15,0x8c,0xf1,0xb1,0xdb,0xee,0x07,0x20,0x71,0x0d,0x3c,0xd0,0x01,
    0x39,0x62,0xf8,0x9b,0x45,0x10,0x57,0xb0,0x50,0x2d,0x64,0xeb,0x7c,0xae,0x18,0xea,0x1c,0x82,
    0x0b,0xc7,0x26,0x94,0xc8,0x6e,0xe6,0xe3,0xc4,0x28,0x66,0xb2,0x8d,0x69,0x19,0xe3,0xed,0x0a,
    0x53,0x57,0x97,0x38,0x58,0xa2,0x03,0xe9,0x17,0x05,0x03,0xe5,0x86,0xfa,0x81,0x5a,0x36,0x38,
    0x6d,0x7f,0xf1,0xd5,0xd8,0xd4,0xaa,0xe5,0x92,0xbf,0x6f,0xd9,0xe2,0x2f,0x34,0x5c,0x1e,0x23,
    0xe6,0xe5,0x72,0x93,0x92,0xc5,0x36,0x84,0x7a,0xbc,0xa5,0x99,0x11,0x31,0x08,0x7b,0x80,0xa0,
    0xf8,0x40,0x2a,0xb1,0x48,0xed,0x16,0x29,0x42,0xc2,0x53,0xca,0x95,0xa9,0x8e,0x12,0x34,0x89,
    0xca,0xaf,0x80,0xea,0xd4,0x9d,0x8c,0xdb,0x94,0xf4,0x6a,0xdb,0xd1,0xfa,0xaf,0x2a,0xc2,0xa6,
    0xd5,0x0f,0x2e,0xd9,0xd2,0xa3,0x2d,0x90,0xbc,0xd3,0xb7,0x33,0xd0,0x34,0x8b,0x38,0xf0,0xac,
    0x6d,0x2c,0x8e,0xcd,0x95,0xb8,0x99,0x84,0x92,0xef,0xcb,0x93
    };  //sign tst_enc_data2


static unsigned char tst_cmac_key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
	0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};


static unsigned char tst_cmac_data[64] = {
	    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};//cmac test data

static unsigned char tst_hmac_data[] = "some data to hash";

static unsigned char tst_base64_data[] = {0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
    0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
    0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
    0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
    0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
    0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
    0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
    0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97};

static unsigned char tst_base64_dec[] = "MHcCAQEEIF+sZpvsUDW1sjsWUVGOF9mg8ETUA5pOZo2qpGE2lu98oAoGCCqBHM9VAYItoUQDQgAEvUnGEEEStuP8jsxAyjPSKkxTd/j2Y0kc3oZisPblRKMEVLJXAlmb9tdD0tb35AuH640H+c+/84hYUnu2L1wxng==";

static unsigned char tst_hash_data2[] = "1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678\
1234567812345678123456781234567812345678";

static unsigned char tst_hash_data3[] = "abcdefg";

static unsigned char outbuf1[4096];
static int outbuf1len;
static unsigned char outbuf2[4096];
static int outbuf2len;

vc_storage_key_st tst_sto_asym_pub_key;
vc_storage_key_st tst_sto_asym_priv_key;
u8 keymac[32] = {0};
u8 keymac2[32] = {0};
/*****************************/



void Hex_PRINTF(uint8_t *buf, int32_t len,uint8_t *tag)
{
    int32_t i;
    int32_t binstr_len = len*2+1;
    int8_t binstr[binstr_len];
    memset(binstr,0,binstr_len);
    for(i=0;i<len;i++)
    {
        sprintf(binstr,"%s%02x",binstr,buf[i]);
    }
    printf("%s == %s\n",tag,binstr);
}




int TST_RSA_SIGN()
{
    int res = 0;

    vc_rsa_sigver_st rsaSVInfo = {0};
    rsaSVInfo.hash_type = HASH_MD_SHA1;//HASH_MD_SHA1;
    vc_rsa_encdec_st *rsaEncDecInfo = &(rsaSVInfo.encinfo);

    rsaEncDecInfo->keyID = tst_sto_asym_priv_key.keyID;                //use rsa enc,dec key
    rsaEncDecInfo->rsa_padding_mode = RSA_PKCS_V15;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    //unsigned char outbuf[2048] = {0};
    memset(outbuf1, 0, 2048);
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    res = vc_rsa_sign(&rsaSVInfo, &indata, &outdata);

    printf("res %d \n",res);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_sign  %d\n", outdata.dataSize);
    }
    printf("TST_RSA_SING res %d\n", res);
    outbuf1len = outdata.dataSize;

    return res;
}

int TST_RSA_VERIFY()
{
    int res = 0;

    vc_rsa_sigver_st rsaSVInfo = {0};
    rsaSVInfo.hash_type = HASH_MD_SHA1;
    vc_rsa_encdec_st *rsaEncDecInfo = &(rsaSVInfo.encinfo);

    rsaEncDecInfo->keyID = tst_sto_asym_pub_key.keyID;                //use rsa enc,dec key
    rsaEncDecInfo->rsa_padding_mode = RSA_PKCS_V15;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    //unsigned char outbuf[2048] = {0};
   // memset(outbuf2, 0, 2048);
    outdata.data =  outbuf1;
    outdata.dataSize = outbuf1len;

	{
        int i;
        for (i = 0; i < indata.dataSize; i++)
        {
            printf("0x%02x,", indata.data[i]);
        }
        printf("##################################vc_rsa_verify indata %d\n", indata.dataSize);
    }

    res = vc_rsa_verify(&rsaSVInfo, &indata, &outdata);   //in: sign in ; out : sign out

    printf("TST_RSA_VERIFY res %d\n", res);

    return res;
}

int TST_RSA_SIGN_file()
{
    int res = 0;

    vc_rsa_sigver_st rsaSVInfo = {0};
    rsaSVInfo.hash_type = HASH_MD_SHA1;//HASH_MD_SHA1;
    vc_rsa_encdec_st *rsaEncDecInfo = &(rsaSVInfo.encinfo);

    rsaEncDecInfo->keyID = tst_sto_asym_priv_key.keyID;                //use rsa enc,dec key
    rsaEncDecInfo->rsa_padding_mode = RSA_PKCS_V15;

    u8 filepath[] = "./hashtst";

    vc_output_info outdata;
    //unsigned char outbuf[2048] = {0};
    memset(outbuf1, 0, 2048);
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    res = vc_rsa_sign_file(&rsaSVInfo, filepath, &outdata);

    printf("res %d \n",res);
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_sign  %d\n", outdata.dataSize);
    }
    printf("TST_RSA_SING res %d\n", res);
    outbuf1len = outdata.dataSize;

    return res;
}

int TST_RSA_VERIFY_file()
{
    int res = 0;

   vc_rsa_sigver_st rsaSVInfo = {0};
    rsaSVInfo.hash_type = HASH_MD_SHA1;
    vc_rsa_encdec_st *rsaEncDecInfo = &(rsaSVInfo.encinfo);

    rsaEncDecInfo->keyID = tst_sto_asym_pub_key.keyID;                //use rsa enc,dec key
    rsaEncDecInfo->rsa_padding_mode = RSA_PKCS_V15;

    u8 filepath[] = "./hashtst";

    vc_output_info outdata;
    //unsigned char outbuf[2048] = {0};
   // memset(outbuf2, 0, 2048);
    outdata.data =  outbuf1;
    outdata.dataSize = outbuf1len;

    res = vc_rsa_verify_file(&rsaSVInfo, filepath, &outdata);   //in: sign in ; out : sign out

    printf("TST_RSA_VERIFY res %d\n", res);

    return res;
}

int TST_GET_RANDOM()
{
    int res = 0;

    vc_output_info outdata;
    memset(outbuf1, 0, 2048);
    outdata.data = outbuf1;

    res = vc_random_gen(24, &outdata);
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_random_gen  %d\n", outdata.dataSize);
    }
    printf("TST_GET_RANDOM res %d\n", res);

    return res;
}

int TST_RSA_GEN_STO_ENC_DEC()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info pubKey, privKey;
    int paddingMode = RSA_PKCS_V15;
    genKeyInfo.keyLen = 256;
    genKeyInfo.keyType = KEY_TYPE_RSA_PUB;
    genKeyInfo.extInfo = (void *)&paddingMode;
    u8 mac[32] = {0};

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
        printf("TST_GEN_KEY res %d\n", res);
    }

   // vc_storage_key_info storageKeyInfo;
    memset(&tst_sto_asym_pub_key, 0 ,sizeof(vc_storage_key_st));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(vc_storage_key_st));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_RSA_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);

    if (costflag == 0)
        printf("sto pub %d\n", res);

    //vc_storage_key_info storageKeyInfo2;

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_RSA_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);

    if (costflag == 0)
        printf("sto priv %d\n", res);

    int count = 0;
    do
    {
    vc_rsa_encdec_st rsaEncDecInfo;
    rsaEncDecInfo.keyID = tst_sto_asym_pub_key.keyID;
    rsaEncDecInfo.rsa_padding_mode = paddingMode;

    vc_input_info indata;
    indata.data = tst_dec_data3;
    indata.dataSize = 200;

    vc_output_info outdata;

    memset(outbuf1, 0, sizeof(outbuf1));
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    res = 0;
    res = vc_rsa_encrypt(&rsaEncDecInfo, &indata, &outdata);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_encrypt  %d\n", outdata.dataSize);
    }
    if (costflag == 0)
        printf("TST_RSA_ENC res %d\n", res);
    outbuf1len = outdata.dataSize;

    rsaEncDecInfo.keyID = tst_sto_asym_priv_key.keyID;
    rsaEncDecInfo.rsa_padding_mode = paddingMode;

    indata.data = outbuf1;
    indata.dataSize = outbuf1len;

    memset(outbuf2, 0, sizeof(outbuf2));
    outdata.data =  outbuf2;
    outdata.dataSize = 1024;

    res = vc_rsa_decrypt(&rsaEncDecInfo, &indata, &outdata);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_decrypt  %d\n", outdata.dataSize);
    }
    if (costflag == 0)
        printf("TST_RSA_DEC res %d\n", res);
    count ++;

    }
    while (0);//(res == 0);

#if 0
    //export key plain
    vc_except_key expk;
    expk.KeyID = tst_sto_asym_pub_key.keyInfo.keyID;
    expk.trans_mod = TRANS_CIPHER_P_DBG;
    expk.EncInfo = NULL;

    vc_output_info expkey;
    memset(outbuf1, 0, sizeof(outbuf1));
    expkey.data = outbuf1;
    expkey.dataSize = sizeof(outbuf1);
    res = vc_export_key(&expk, &expkey);
    if (res == 0)
        printf("#######exp %d\n%s\n", expk.KeyID, expkey.data);
#endif

   // res = vc_storage_key(&tst_sto_asym_pub_key, 1);
  //  res = vc_storage_key(&tst_sto_asym_priv_key, 1);

    return res;
}

int TST_ECC_GEN_STO_SIG_VEF()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    ecc_group_id ecid = ECP_DP_SECP256K1;//ECP_DP_CURVE25519;//ECP_DP_SECP256K1;//
    vc_output_info pubKey, privKey;
    genKeyInfo.keyType = KEY_TYPE_ECC_PUB;
    genKeyInfo.extInfo = (void *)&ecid;

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
    }

    if (costflag == 0)
        printf("TST_GEN_KEY res %d\n", res);

    memset(&tst_sto_asym_pub_key, 0 ,sizeof(tst_sto_asym_pub_key));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(tst_sto_asym_priv_key));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_ECC_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);

    if (costflag == 0)
        printf("sto priv %d\n", res);

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_ECC_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);

    if (costflag == 0)
        printf("sto pub %d\n", res);

    vc_ecc_sigver_st ecSigVer;
    ecSigVer.keyID = tst_sto_asym_priv_key.keyID;
    ecSigVer.hash_type = HASH_MD_SHA512;

    vc_input_info indata;
    indata.data = tst_enc_data3;
    indata.dataSize = sizeof(tst_enc_data3);

    vc_output_info outdata;

    memset(outbuf1, 0, sizeof(outbuf1));
    outdata.data =  outbuf1;
    outdata.dataSize = 1024;

    vc_output_info outdata2;

    memset(outbuf2, 0, sizeof(outbuf2));
    outdata2.data =  outbuf2;
    outdata2.dataSize = 1024;

    res = vc_ecdsa_sign(&ecSigVer, &indata, &outdata, &outdata2);
    if (costflag == 0)
        printf("ecdsa  sign  res %d\n", res);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################outdata  %d\n", outdata.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata2.dataSize; i++)
        {
            printf("0x%02x,", outdata2.data[i]);
        }
        printf("##################################outdata2  %d\n", outdata2.dataSize);
    }


    ecSigVer.keyID = tst_sto_asym_pub_key.keyID;
    ecSigVer.hash_type = HASH_MD_SHA512;
    res = vc_ecdsa_verify(&ecSigVer, &indata, &outdata, &outdata2);
    if (costflag == 0)
        printf("ecdsa  verify  res %d\n", res);

    return res;
}

int TST_ECDH_25519()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    ecc_group_id ecid = ECP_DP_CURVE25519;//
    vc_output_info pubKey, privKey;

    genKeyInfo.keyType = KEY_TYPE_ECDH_25519;
    genKeyInfo.extInfo = (void *)&ecid;


    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < pubKey.dataSize ;i++)
            printf("%02x,", pubKey.data[i]);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < privKey.dataSize ;i++)
            printf("%02x,", privKey.data[i]);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
    }

    vc_output_info pubKey2, privKey2;
    u8 b1[128];
    u8 b2[128];
    pubKey2.data = b1;
    pubKey2.dataSize = 128;

    privKey2.data = b2;
    privKey2.dataSize = 128;

    res = vc_asym_genkey(&genKeyInfo , &pubKey2, &privKey2);
    {
        int i;
        for (i = 0; i < pubKey2.dataSize ;i++)
            printf("%02x,", pubKey2.data[i]);
        printf("##################################vc_asym_genkey2  pub %d\n", pubKey2.dataSize);
    }

    {
        int i;
        for (i = 0; i < privKey2.dataSize ;i++)
            printf("%02x,", privKey2.data[i]);
        printf("##################################vc_asym_genkey2  priv %d\n", privKey2.dataSize);
    }

    vc_output_info skey;
    u8 skdata[64];
    skey.data = skdata;
    skey.dataSize = 64;

    res = vc_ecdh_shared_key((vc_input_info *)&privKey, (vc_input_info *)&pubKey2, &skey);
    if (res == 0)
    {
        int i;
        for (i = 0; i < skey.dataSize ;i++)
            printf("%02x,", skey.data[i]);
        printf("##################################ssskkk  %d\n", skey.dataSize);
    }

    vc_output_info skey2;
    u8 skdata2[64];
    skey2.data = skdata2;
    skey2.dataSize = 64;

    res = vc_ecdh_shared_key((vc_input_info *)&privKey2, (vc_input_info *)&pubKey, &skey2);
    if (res == 0)
    {
        int i;
        for (i = 0; i < skey2.dataSize ;i++)
            printf("%02x,", skey2.data[i]);
        printf("##################################ssskkk222  %d\n", skey2.dataSize);
    }

    printf("TST_ECDH_25519 res %d\n", res);
    return res;
}

#ifdef SMENABLE

int TST_SM2_GEN_STO_ENC_DEC()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info pubKey, privKey;
    genKeyInfo.keyType = KEY_TYPE_SM2_PUB;

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);

        int i;
        for (i = 0 ; i < pubKey.dataSize; i++)
            printf("%02x ",pubKey.data[i]);

        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }

    if (costflag == 0)
        printf("TST_RSA_DEC res %d\n", res);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
    }
    if (costflag == 0)
        printf("TST_GEN_KEY res %d\n", res);

    memset(&tst_sto_asym_pub_key, 0 ,sizeof(tst_sto_asym_pub_key));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(tst_sto_asym_priv_key));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_SM2_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);

    printf("sto pub %d\n", res);

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_SM2_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);

    printf("sto priv %d\n", res);


    vc_input_info indata;
    indata.data = tst_dec_data3;
    indata.dataSize = 200;

    vc_output_info outdata;

    memset(outbuf1, 0, sizeof(outbuf1));
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    vc_sm2_encdec_st encinfo = {0};
    encinfo.keyID = tst_sto_asym_pub_key.keyID;

    res = vc_sm2_enc(&encinfo, &indata, &outdata);

    printf("vc_sm2_enc res %d\n", res);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_sm2_enc  %d\n", outdata.dataSize);
    }

    encinfo.keyID = tst_sto_asym_priv_key.keyID;

    indata.data = outdata.data;
    indata.dataSize = outdata.dataSize;

    outdata.data = outbuf2;
    outdata.dataSize = 2048;
    res = vc_sm2_dec(&encinfo, &indata, &outdata);
    printf("vc_sm2_dec   res %d\n", res);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_sm2_dec  %d\n", outdata.dataSize);
    }

    return res;
}
#endif

int TST_AES_GEN_STO_ENC_DEC_MOD()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info aesKeyInfo;
    genKeyInfo.keyLen = 16;
    genKeyInfo.keyType = KEY_TYPE_AES;
    u8 mac[32] ={0};


    memset(outbuf1, 0, sizeof(outbuf1));
    aesKeyInfo.data = outbuf1;

    res = vc_sym_genkey(&genKeyInfo , &aesKeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < aesKeyInfo.dataSize; i++)
        {
            printf("0x%02x,", aesKeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", aesKeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};

    //storageKeyInfo.isWhiteBoxEnc = 0;
    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;
    storageKeyInfo.keyData.data = aesKeyInfo.data;
    storageKeyInfo.keyData.dataSize = aesKeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);
    printf("sto key %d\n", res);

    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CFB;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = NO_PADDING;//PKCS7_PADDING;


    aesEncDecInfo.keyID = storageKeyInfo.keyID;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    unsigned char outbuf[1024];
    outdata.data =  outbuf;
    outdata.dataSize = 1024;

    res = vc_aes_encrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_aes_encrypt  %d\n", outdata.dataSize);
    }
    printf("TST_AES_ENC res %d  mod %d\n", res, aesEncDecInfo.aes_enc_mode );

    aesEncDecInfo.aes_enc_mode = AES_ENC_CFB;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = NO_PADDING;

    aesEncDecInfo.keyID = storageKeyInfo.keyID;

    indata.data = outbuf;
    indata.dataSize = outdata.dataSize;

    outdata.data =  outbuf1;
    outdata.dataSize = sizeof(outbuf1);

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x ", outdata.data[i]);
        }
        printf("##################################vc_aes_decrypt  %d\n", outdata.dataSize);
    }
    printf("vc_aes_decrypt res %d\n", res);

  /*  vc_storage_key_st delInfo;
    delInfo.keyID = storageKeyInfo.keyID;
    delInfo.keyMac = storageKeyInfo.keyMac;
    res = vc_delete_key(&delInfo);
    printf("stodle key %d\n", res);*/

    return res;
}

int TST_AES_GEN_STO_ENC_DEC_gcm()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info aesKeyInfo;
    genKeyInfo.keyLen = 32;
    genKeyInfo.keyType = KEY_TYPE_AES;
    u8 mac[32] ={0};

    memset(outbuf1, 0, sizeof(outbuf1));
    aesKeyInfo.data = outbuf1;

    res = vc_sym_genkey(&genKeyInfo , &aesKeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < aesKeyInfo.dataSize; i++)
        {
            printf("0x%02x,", aesKeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", aesKeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};

    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;

    storageKeyInfo.keyData.data = aesKeyInfo.data;
    storageKeyInfo.keyData.dataSize = aesKeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);

    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_GCM;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;

    aesEncDecInfo.keyID = storageKeyInfo.keyID;

    vc_aes_gcm_encdec_ext_st gcm = {0};

	gcm.addData = tst_enc_gcm_add;
	gcm.addLen = 21;

    aesEncDecInfo.gcm = &gcm;

    vc_input_info indata;
    indata.data = tst_enc_data3;
    indata.dataSize = 67;

    vc_output_info outdata;
    unsigned char outbuf[1024];
    outdata.data =  outbuf;
    outdata.dataSize = 1024;

    res = vc_aes_encrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_aes_encrypt gcm %d\n", outdata.dataSize);

        for (i = 0; i < 16; i++)
        {
            printf("0x%02x,", gcm.tagBuf[i]);
        }
        printf("##################################vc_aes_encrypt gcm tag00\n");
    }
    printf("TST_AES_ENC res %d\n", res);

    aesEncDecInfo.aes_enc_mode = AES_ENC_GCM;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;

    aesEncDecInfo.keyID = storageKeyInfo.keyID;

	gcm.addData = tst_enc_gcm_add;
	gcm.addLen = 21;
	memcpy(gcm.tagVerify, gcm.tagBuf, 16);
    memset(gcm.tagBuf, 0, 16);
    aesEncDecInfo.gcm = &gcm;

    indata.data = outbuf;
    indata.dataSize = outdata.dataSize;

    outdata.data =  outbuf1;
    outdata.dataSize = sizeof(outbuf1);

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x ", outdata.data[i]);
        }
        printf("##################################vc_aes_decrypt  %d\n", outdata.dataSize);

	}
    printf("vc_aes_decrypt res %d\n", res);

    vc_storage_key_st delInfo = {0};
    delInfo.keyID = storageKeyInfo.keyID;
    delInfo.keyMac = storageKeyInfo.keyMac;
    res = vc_delete_key(&delInfo);
    printf("stodle key %d\n", res);

    return res;
}

#ifdef SMENABLE
int TST_SM4_GEN_STO_ENC_DEC_cbc()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info SM4KeyInfo;
    genKeyInfo.keyLen = 16;
    genKeyInfo.keyType = KEY_TYPE_SM4;
    u8 mac[32] ={0};

    memset(outbuf1, 0, sizeof(outbuf1));
    SM4KeyInfo.data = outbuf1;

    res = vc_sym_genkey(&genKeyInfo , &SM4KeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < SM4KeyInfo.dataSize; i++)
        {
            printf("0x%02x,", SM4KeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", SM4KeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};


    storageKeyInfo.isWhiteBoxEnc = 0;
    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;

    storageKeyInfo.keyData.data = SM4KeyInfo.data;
    storageKeyInfo.keyData.dataSize = SM4KeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);
    printf("TST_SM4_GEN_STO_ENC_DEC_cbc , vc_storage_key %d\n", res);

    vc_sm4_encdec_st sm4encInfo = {0};
    sm4encInfo.enc_mode = SM4_ENC_CTR;//SM4_ENC_OFB;//SM4_ENC_CFB;  //SM4_ENC_ECB;//SM4_ENC_CBC;
    sm4encInfo.keyID = storageKeyInfo.keyID;
    memset(tst_iv,0,16);
    sm4encInfo.iv = tst_iv;
    sm4encInfo.padding_mode = PKCS7_PADDING;

    vc_input_info indata;
    indata.data = tst_enc_data3;
    indata.dataSize = 67;

    vc_output_info outdata;
    unsigned char outbuf[1024];
    outdata.data =  outbuf;
    outdata.dataSize = 1024;

    res = vc_sm4_encrypt(&sm4encInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_sm4_encrypt  %d\n", outdata.dataSize);
    }


    memset(tst_iv,0,16);
    sm4encInfo.iv = tst_iv;

    indata.data = outbuf;
    indata.dataSize = outdata.dataSize;

    outdata.data =  outbuf1;
    outdata.dataSize = sizeof(outbuf1);

    res = vc_sm4_decrypt(&sm4encInfo, &indata, &outdata);
    printf("##################################vc_sm4_decrypt0  %d\n", outdata.dataSize);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x ", outdata.data[i]);
        }
        printf("##################################vc_sm4_decrypt  %d\n", outdata.dataSize);
    }

    printf("TST_SM4_GEN_STO_ENC_DEC_cbc res %d\n", res);

    return res;
}
#endif

s32 TST_STO_DEC_PARSE_CRT_KEY()
{
    s32 res = 0;

    vc_storage_crt_st storageCrtInfo = {0};
    u8 mac[32] = {0};
    storageCrtInfo.crtData.data = outbuf1;
    storageCrtInfo.crtData.dataSize = sizeof(outbuf1);
    storageCrtInfo.crtMac = mac;
    storageCrtInfo.isWhiteBoxEnc = 0;

    u8 filepath[] = "./ca-cert.pem";

    vc_output_info output;
	output.data = outbuf1;
	output.dataSize = 4096;

    FILE*fp;

    fp = fopen(filepath, "rb");
    if (fp == NULL)
        printf("fopen eeee0 %s\n", fp);
    storageCrtInfo.crtData.dataSize = fread (storageCrtInfo.crtData.data, 1, 4096, fp) + 1;
    fclose(fp);

    res = vc_storage_crt(&storageCrtInfo);

    vc_output_info output2;
	output2.data = outbuf2;
	output2.dataSize = 2048;

    res = vc_parse_crt_pubkey(storageCrtInfo.crtID, &output2);
    if (res == 0)
    {
        int i;
        for (i = 0; i < output2.dataSize; i++)
        {
            printf("%02x ", output2.data[i]);
        }
        printf("##################################output  %d\n", output2.dataSize);

        printf("\n %s \n####pub \n", output2.data);
    }

    res = vc_delete_crt(&storageCrtInfo);

    return res;
}

s32 TST_VER_CRT()
{
    s32 res = 0;

    vc_storage_crt_st storageCrtInfo = {0};
    u8 mac[32] = {0};
    storageCrtInfo.crtData.data = outbuf1;
    storageCrtInfo.crtData.dataSize = sizeof(outbuf1);
    storageCrtInfo.crtMac = mac;
    storageCrtInfo.isWhiteBoxEnc = 0;

    vc_output_info crt;
	crt.data = outbuf2;
	crt.dataSize = 4096;
    memset(outbuf2, 0 , 4096);

    u8 filecrt[] = "client-cert.pem";
    u8 fileca[] = "ca-cert.pem";

    FILE *fpcrt,*fpca;

    fpcrt = fopen(filecrt, "rb");
    if (fpcrt == NULL)
        printf("fopen eeee %s\n", filecrt);
    crt.dataSize = fread (crt.data, 1, 4096, fpcrt) + 1;

    fpca = fopen(fileca, "rb");
    if (fpcrt == NULL)
        printf("fopen eeee0 %s\n", fpca);
    storageCrtInfo.crtData.dataSize = fread (storageCrtInfo.crtData.data, 1, 4096, fpca) + 1;

    res = vc_storage_crt(&storageCrtInfo);

    res = vc_verify_crt((vc_input_info *)&crt, storageCrtInfo.crtID, 0, NULL);
    if (costflag == 0)
        printf("ver crt %d\n", res);

    fclose(fpcrt);
    fclose(fpca);
    return res;
}


s32 TST_GEN_CSR()
{
    s32 res = 0;

    vc_csr_st csr;
    u8 subject_name[] = "abc";

    csr.hashAlg = HASH_MD_SHA256;
    csr.keyID = tst_sto_asym_priv_key.keyID;
    csr.key_usage = 0;
    csr.ns_cert_type = 0;
    csr.subject_name = subject_name;

    vc_output_info output2;
	output2.data = outbuf2;
	output2.dataSize = 2048;

    res = vc_gen_csr(&csr, &output2);

    return res;
}

s32 TST_CALCHMAC()
{
	s32 res = 0;

	/*******gen hmac key and store*********/
	vc_gen_key_st genKeyInfo;
    vc_output_info hmacKeyInfo;
    genKeyInfo.keyLen = 3;
    genKeyInfo.keyType = KEY_TYPE_HMAC;
    u8 mac[32] = {0};

    memset(outbuf1, 0, sizeof(outbuf1));
    hmacKeyInfo.data = outbuf1;

    res = vc_hmac_genkey(&genKeyInfo , &hmacKeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < hmacKeyInfo.dataSize; i++)
        {
            printf("0x%02x,", hmacKeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", hmacKeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};

    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;

    storageKeyInfo.keyData.data = hmacKeyInfo.data;
    storageKeyInfo.keyData.dataSize = hmacKeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);
	/*************************************/

	/*************calc hmac***************/
	vc_hmac_st hmac_info;
	hmac_info.hash_type = HASH_MD_SHA256;
	hmac_info.keyID = storageKeyInfo.keyID;

	vc_input_info input;
	input.data = tst_hmac_data;
	input.dataSize = sizeof(tst_hmac_data) - 1;

	vc_output_info output;
	output.data = outbuf1;
	output.dataSize = 32;

	res = vc_CalcHmac(&hmac_info, &input, &output);
    if (res == 0)
	{
		int i;
        for (i = 0; i < output.dataSize; i++)
        {
            printf("%02x ", output.data[i]);
        }
        printf("##################################hmac  %d\n", output.dataSize);
	}

	printf("##################################TST_CALCHMAC res %d\n", res);

    vc_storage_key_st delInfo = {0};
    delInfo.keyID = storageKeyInfo.keyID;
    delInfo.keyMac = storageKeyInfo.keyMac;
    res = vc_delete_key(&delInfo);
    printf("stodle key %d\n", res);

	return res;
}

s32 TST_CALCCMAC()
{
	s32 res = 0;

	/*******gen hmac key and store*********/
	vc_gen_key_st genKeyInfo = {0};
    vc_output_info cmacKeyInfo;
    genKeyInfo.keyLen = 16;
    genKeyInfo.keyType = KEY_TYPE_CMAC;
    u8 mac[32] ={0};

    memset(outbuf1, 0, sizeof(outbuf1));
    cmacKeyInfo.data = outbuf1;

    res = vc_cmac_genkey(&genKeyInfo , &cmacKeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < cmacKeyInfo.dataSize; i++)
        {
            printf("0x%02x,", cmacKeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", cmacKeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};

    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;

    storageKeyInfo.keyData.data = cmacKeyInfo.data;
    storageKeyInfo.keyData.dataSize = cmacKeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);
	/*************************************/

	/*************calc cmac***************/
	vc_cmac_st cmac_info;
	cmac_info.keyID = storageKeyInfo.keyID;;
	vc_input_info input;
	input.data = tst_hmac_data;
	input.dataSize = sizeof(tst_hmac_data) - 1;

	vc_output_info output;
	output.data = outbuf1;
	output.dataSize = 32;

	res = vc_CalcCmac(&input, &cmac_info, &output);
    if (res == 0)
	{
		int i;
        for (i = 0; i < output.dataSize; i++)
        {
            printf("%02x ", output.data[i]);
        }
        printf("##################################hmac  %d\n", output.dataSize);
	}

	printf("##################################TST_CALCHMAC res %d\n", res);

    res = vc_VerifyCmac(&input, &cmac_info, &output);
    printf("################################ verify cmac %d\n", res);

    vc_storage_key_st delInfo;
    delInfo.keyID = storageKeyInfo.keyID;
    delInfo.keyMac = storageKeyInfo.keyMac;
    res = vc_delete_key(&delInfo);
    printf("stodle key %d\n", res);

	return res;
}

#ifdef SMENABLE
int TST_SM2_SIGN()
{
    u8 id[] = "China";
    vc_sm2_sigver_st sm2SVInfo = {0};
    sm2SVInfo.keyID = 1;
    sm2SVInfo.skeyID = 2;//tst_sto_asym_priv_key.keyID;
    sm2SVInfo.id = id;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    memset(outbuf1, 0, 2048);
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    int res = 0;
    /***************/
    #if 0

    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CBC;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;//PKCS7_PADDING;

    aesEncDecInfo.keyID = 3;

    vc_except_key_st exceptKeyInfo;
    exceptKeyInfo.EncInfo = (void *)&aesEncDecInfo;
    exceptKeyInfo.KeyID = 1;//public key id
    exceptKeyInfo.trans_mod = TRANS_CIPHER_AES;

   // vc_input_info indata;

    vc_output_info pubkeyEnc;
    //vc_output_info pubkeyDec;
    unsigned char outbuf[1024] = {0x00};
    pubkeyEnc.data =  outbuf;
    pubkeyEnc.dataSize = 1024;

    res = vc_export_key(&exceptKeyInfo,&pubkeyEnc);

    printf("--------------pubkeyEnc.dataSize len = %d \n", pubkeyEnc.dataSize);

    memset(tst_iv,0,16);

    aesEncDecInfo.keyID = 3;

    indata.data = outbuf;
    indata.dataSize = pubkeyEnc.dataSize;

    vc_output_info pubkeyDec;
    //vc_output_info pubkeyDec;
    unsigned char outbufa[1024] = {0x00};
    pubkeyDec.data =  outbufa;
    pubkeyDec.dataSize = 1024;

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, &pubkeyDec);
    if (res == 0)
    {
        int i;
        for (i = 0; i < pubkeyDec.dataSize; i++)
        {
            printf("%02x ", pubkeyDec.data[i]);
        }
        printf("##################################vc_aes_decrypt  %d\n", pubkeyDec.dataSize);
    }
    #endif
    /***************/

   // int res = 0;
    res = vc_sm2_sign(&sm2SVInfo, &indata, &outdata);
    if (costflag == 0)
        printf("vc_sm2_sign res %d \n",res);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_sign  %d\n", outdata.dataSize);
    }
    printf("TST_SM2_SIGN res %d\n", res);
    outbuf1len = outdata.dataSize;

    return res;
}

int TST_SM2_VERIFY()
{
    u8 id[] = "China";
    vc_sm2_sigver_st sm2SVInfo = {0};
    sm2SVInfo.keyID = 1;//tst_sto_asym_pub_key.keyID;
    sm2SVInfo.id = id;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    outdata.data =  outbuf1;
    outdata.dataSize = outbuf1len;

    {
        printf("------  src data ------------\n");
        int i;
        for (i = 0; i < indata.dataSize; i++)
        {
            printf("%02x", indata.data[i]);
        }
        printf("##################################TST_SM2_VERIFY indata %d\n", indata.dataSize);
    }

    int res = 0;
    res = vc_sm2_verify(&sm2SVInfo, &indata, &outdata);   //in: sign in ; out : sign out
    if (costflag == 0)
        printf("vc_sm2_verify res %d \n",res);
    if (res == 0 && costflag == 0)
    {
        printf("--------r s outdata ----------\n");
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x", outdata.data[i]);
        }
        printf("##################################vc_rsa_verify  %d\n", outdata.dataSize);
    }
    printf("TST_SM2_VERIFY res %d\n", res);

    return res;
}
#endif

static u8 fileBuf[10400] = {0};
static u8 outBuf3[10400] = {0};
static u32 fileBlock = 0;
static u32 filePadding = 0;

s32 TST_HASH()
{
    s32 res = 0;
    vc_hash_st hashInfo;
    hashInfo.hash_type = HASH_MD_SHA512;//HASH_SM3;

    vc_input_info indata;
    indata.data = tst_hash_data3;
    indata.dataSize = sizeof(tst_hash_data3) - 1 ;
    printf("sizieof %d\n", indata.dataSize);

    vc_output_info outdata;
    outdata.data =  outbuf1;
    outdata.dataSize = 4096;

    res = vc_hash(&hashInfo, &indata, &outdata);
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_hash  %d\n", outdata.dataSize);
    }
    printf("TST_HASH res %d\n", res);


    vc_output_info outdata2;
    memset(outbuf2, 0, 4096);
    outdata2.data =  outbuf2;
    outdata2.dataSize = 4096;
    u8 filepath[] = "./hashtst";

    vc_hash_file(&hashInfo,filepath, &outdata2);
    {
        int i;
        for (i = 0; i < outdata2.dataSize; i++)
        {
            printf("0x%02x,", outdata2.data[i]);
        }
        printf("##################################vc_hashtttttttttttt  %d\n", outdata2.dataSize);
    }

    return res;
}

s32 TST_BASE64_ENCODE()
{
    s32 res;

    vc_input_info indata;
    indata.data = tst_base64_data;
    indata.dataSize = 64;

    vc_output_info outdata;
    outdata.data =  outBuf3;
	outdata.dataSize = 10400;

    res = vc_Base64Encode(&indata, &outdata);

    {
		int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%c", outdata.data[i]);
        }
        printf("\n##################################base64  %d\n", outdata.dataSize);
	}

    printf("TST_BASE64_ENCODE %d\n",res);

    return res;
}

s32 TST_BASE64_DECODE()
{
    s32 res;

    vc_input_info indata;
    indata.data = tst_base64_dec;
    indata.dataSize = 64;

    vc_output_info outdata;
    outdata.data =  outBuf3;
	outdata.dataSize = 10400;

    res = vc_Base64Decode(&indata, &outdata);

    {
		int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%x ", outdata.data[i]);
        }
        printf("\n##################################base64  %d\n", outdata.dataSize);
	}

    printf("TST_BASE64_deCODE %d\n",res);

    return res;
}

s32 TST_ENVELOPE_SEAL_OPEN()
{
    s32 res = 0;

    vc_gen_key_st genKeyInfo;
    vc_output_info pubKey, privKey;
    int paddingMode = RSA_PKCS_V15;
    genKeyInfo.keyLen = 128;
    genKeyInfo.keyType = KEY_TYPE_RSA_PUB;
    genKeyInfo.extInfo = (void *)&paddingMode;

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }

    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
    }

    printf("TST_GEN_KEY res %d\n", res);

    memset(&tst_sto_asym_pub_key, 0 ,sizeof(vc_storage_key_st));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(vc_storage_key_st));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_RSA_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);

    printf("sto pub %d\n", res);

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_RSA_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);

    printf("sto priv %d\n", res);

    vc_envelope_in_st envIn = {0};
    u8 IV[16] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf};
    envIn.keyID = tst_sto_asym_pub_key.keyID ;
    envIn.iv = IV;
    envIn.aes_enc_mode = AES_ENC_CBC;
    envIn.aesKeyLen = 16;

    vc_input_info indata;
    indata.data = tst_base64_data;
    indata.dataSize = 50;

    vc_envelope_out_st envOut = {0};
    envOut.aeskeycipher.data = outbuf1;
    envOut.aeskeycipher.dataSize = 2048;
    envOut.cipher.data = outbuf2;
    envOut.cipher.dataSize = 2048;

    res = vc_enveloped_seal(&envIn, &indata, &envOut);
    printf("TST_ENVELOPE_SEAL_OPEN vc_enveloped_seal res %d\n", res);


    u8 outplain[2048] = {0};

    envOut.keyID = tst_sto_asym_priv_key.keyID ;
    envOut.iv = IV;
    envOut.aes_enc_mode = AES_ENC_CBC;

    vc_output_info outdata;
    outdata.data = outplain;
    outdata.dataSize = 2048;
    res = vc_enveloped_openseal(&envOut, &outdata);
    printf("TST_ENVELOPE_SEAL_OPEN vc_enveloped_openseal res %d\n", res);
    if (res == 0 &&  costflag == 0)
    {
		int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x ", outdata.data[i]);
        }
        printf("\n##################################open  %d\n", outdata.dataSize);
	}


    return res;
}

s32 TST_ECC_GEN_ENC_DEC()
{
    s32 res =0;

    vc_gen_key_st genKeyInfo = {0};
    ecc_group_id ecid = ECP_DP_SECP256K1;//ECP_DP_SECP521R1;//ECP_DP_CURVE25519;//ECP_DP_SECP256K1;//
    vc_output_info pubKey, privKey;
    genKeyInfo.keyType = KEY_TYPE_ECC_PUB;
    genKeyInfo.extInfo = (void *)&ecid;

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
        printf("TST_GEN_KEY res %d\n", res);
    }

    memset(&tst_sto_asym_pub_key, 0 ,sizeof(tst_sto_asym_pub_key));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(tst_sto_asym_priv_key));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_ECC_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);

    if (costflag == 0)
        printf("sto priv %d\n", res);

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_ECC_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);

    if (costflag == 0)
        printf("sto pub %d\n", res);

    vc_output_info input;
   //u8 inbuf[64] = {0x00,0x01,0x02,0x00,0x00,0x03,0x06,0x09,
   //                 0x0c,0x0f,0x05,0x0a,0x07,0x0b,0xfe,0xfc};


    unsigned char inbuf[258] = {0x00,0x48,0x24,0xf1,0xca,0x5c,0xbf,0x07,0xe8,0x4d,0xc0,
        0x9c,0x71,0x59,0xe0,0x93,0xb1,0x42,0x52,0x1c,0xa2,
        0x4a,0xfc,0x74,0xe9,0x74,0xf6,0xa3,0x60,0x5a,0x6e,
        0x31,0x89,0x2c,0xec,0x96,0x13,0x41,0x7e,0x03,0xe6,
        0xb2,0x37,0x8a,0x8a,0xc1,0xa6,0xc6,0x90,0xd4,0x47,
        0x8f,0x02,0xaf,0x62,0x5b,0xf4,0x34,0x61,0x05,0xde,
        0x8c,0xd4,0xef,0x9d,0x70,0x61,0x5d,0x9a,0x0f,0x0e,
        0x7b,0xfe,0x1f,0x85,0x3c,0x1f,0xe5,0x2b,0x06,0xf2,
        0x5a,0x5a,0x87,0xc5,0x9a,0x6a,0x2b,0xa2,0x72,0x75,
        0x4c,0x5e,0x7f,0xda,0x3b,0x14,0xe1,0xa9,0xe4,0x1a,
        0x60,0xa9,0x7c,0x2a,0x94,0x0c,0xcd,0x79,0x91,0x19,
        0x22,0x98,0x32,0xd0,0xc2,0xa8,0x07,0xc3,0x17,0x2c,
        0xf6,0x03,0x6d,0x02,0xe4,0x58,0x70,0x5d,0x6d,0x78,
        0x87,0xd9,0xdb,0xd1,0xc7,0xc6,0x92,0xf7,0x09,0x4c,
        0xf2,0x9b,0x51,0x4c,0xdf,0xd1,0xb5,0x1d,0xa2,0xa5,
        0xf6,0x25,0xe2,0x33,0x0b,0x37,0x70,0x2c,0x55,0xec,
        0xea,0x63,0x53,0xd6,0x08,0x10,0x89,0xb9,0x2c,0xde,
        0xc9,0xe6,0x49,0x6a,0x3f,0x2e,0x6b,0xda,0xb5,0x9c,
        0x8c,0x53,0x71,0xf4,0x97,0xce,0xb8,0xb8,0xac,0xe7,
        0xc9,0x29,0xe7,0x0c,0x0e,0xc5,0x3c,0x2b,0x81,0xbf,
        0xf6,0x24,0x63,0xc5,0x02,0x8b,0x6b,0x18,0xe9,0x83,
        0x4a,0x14,0x3c,0x52,0xc2,0xde,0x04,0xff,0xe7,0x0f,
        0xfc,0x04,0x3c,0x7b,0x71,0x1c,0x79,0xf5,0xf5,0xf6,
        0xa2,0x00,0x36,0x81,0x67,0x70,0x2e,0x56,0x76,0x4c,
        0xc3,0x11,0x76,0xaa,0x8f,0x6a,0xf1,0xe2,0x8b,0xce,
        0x87,0xd9,0xc1,0xf1,0x7f};

    input.data = inbuf;
    input.dataSize = 200;

    vc_output_info out;
    u8 outbuff[2048] = {0};
    out.data = outbuff;
    out.dataSize = 2048;

    vc_ecc_encdec_st encInfo;
    encInfo.keyID = tst_sto_asym_pub_key.keyID;
    encInfo.hash_type = HASH_MD_SHA256;

    res = vc_ecc_enc(&encInfo, (vc_input_info *)&input, &out);
    if (costflag == 0)
        printf("enc res %d\n", res);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < out.dataSize; i++)
        {
            printf("%02x ", out.data[i]);
        }
        printf("\n##################################outenc  %d\n", out.dataSize);
    }

    vc_output_info out2;
    u8 outbuff2[2048] = {0};
    out2.data = outbuff2;
    out2.dataSize = 2048;

    encInfo.keyID = tst_sto_asym_priv_key.keyID;
    encInfo.hash_type = HASH_MD_SHA256;

    res = vc_ecc_dec(&encInfo, (vc_input_info *)&out, &out2);
    if (costflag == 0)
        printf("dec res %d\n", res);
    if (res == 0 && costflag == 0)
     {
        int i;
        for (i = 0; i < out2.dataSize; i++)
        {
            printf("%02x ", out2.data[i]);
        }
        printf("\n##################################outdec  %d\n", out2.dataSize);
    }

    res = vc_delete_key(&tst_sto_asym_pub_key);
    res = vc_delete_key(&tst_sto_asym_priv_key);

    return res;
}

int TST_AES_TMP_GEN_STO_ENC_DEC_MOD()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info aesKeyInfo;
    genKeyInfo.keyLen = 16;
    genKeyInfo.keyType = KEY_TYPE_AES;
    u8 mac[32] ={0};


    memset(outbuf1, 0, sizeof(outbuf1));
    aesKeyInfo.data = outbuf1;

    res = vc_sym_genkey(&genKeyInfo , &aesKeyInfo);
    if (res == 0)
    {
        int i;
        for (i = 0; i < aesKeyInfo.dataSize; i++)
        {
            printf("0x%02x,", aesKeyInfo.data[i]);
        }
        printf("##################################vc_sym_genkey  %d\n", aesKeyInfo.dataSize);
    }
    printf("vc_sym_genkey res %d\n", res);

    vc_storage_key_st storageKeyInfo = {0};

    //storageKeyInfo.isWhiteBoxEnc = 0;
    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;
    storageKeyInfo.keyData.data = aesKeyInfo.data;
    storageKeyInfo.keyData.dataSize = aesKeyInfo.dataSize;

    res = vc_storage_tmp_key(&storageKeyInfo);
    printf("sto key %d\n", res);

    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CFB;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = NO_PADDING;//PKCS7_PADDING;


    aesEncDecInfo.keyID = storageKeyInfo.keyID;

    vc_input_info indata;
    indata.data = tst_enc_data2;
    indata.dataSize = 26;

    vc_output_info outdata;
    unsigned char outbuf[1024];
    outdata.data =  outbuf;
    outdata.dataSize = 1024;

    res = vc_aes_encrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_aes_encrypt  %d\n", outdata.dataSize);
    }
    printf("TST_AES_ENC res %d  mod %d\n", res, aesEncDecInfo.aes_enc_mode );

    aesEncDecInfo.aes_enc_mode = AES_ENC_CFB;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = NO_PADDING;

    aesEncDecInfo.keyID = storageKeyInfo.keyID;

    indata.data = outbuf;
    indata.dataSize = outdata.dataSize;

    outdata.data =  outbuf1;
    outdata.dataSize = sizeof(outbuf1);

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, &outdata);
    if (res == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("%02x ", outdata.data[i]);
        }
        printf("##################################vc_aes_decrypt  %d\n", outdata.dataSize);
    }
    printf("vc_aes_decrypt res %d\n", res);

    vc_storage_key_st delInfo;
    delInfo.keyID = storageKeyInfo.keyID;
    delInfo.keyMac = storageKeyInfo.keyMac;
    res = vc_delete_tmp_key(&delInfo);
    printf("stodle key %d\n", res);

    return res;
}

int TST_RSA_TMP_GEN_STO_ENC_DEC()
{
    int res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info pubKey, privKey;
    int paddingMode = RSA_PKCS_V15;
    genKeyInfo.keyLen = 256;
    genKeyInfo.keyType = KEY_TYPE_RSA_PUB;
    genKeyInfo.extInfo = (void *)&paddingMode;
    u8 mac[32] = {0};

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
        printf("TST_GEN_KEY res %d\n", res);
    }

   // vc_storage_key_info storageKeyInfo;
    memset(&tst_sto_asym_pub_key, 0 ,sizeof(vc_storage_key_st));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(vc_storage_key_st));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_RSA_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_tmp_key(&tst_sto_asym_pub_key);

    if (costflag == 0)
        printf("sto pub %d\n", res);

    //vc_storage_key_info storageKeyInfo2;

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_RSA_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_tmp_key(&tst_sto_asym_priv_key);

    if (costflag == 0)
        printf("sto priv %d\n", res);

    int count = 0;
    do
    {
    vc_rsa_encdec_st rsaEncDecInfo;
    rsaEncDecInfo.keyID = tst_sto_asym_pub_key.keyID;
    rsaEncDecInfo.rsa_padding_mode = paddingMode;

    vc_input_info indata;
    indata.data = tst_dec_data3;
    indata.dataSize = 200;

    vc_output_info outdata;

    memset(outbuf1, 0, sizeof(outbuf1));
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    res = 0;
    res = vc_rsa_encrypt(&rsaEncDecInfo, &indata, &outdata);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_encrypt  %d\n", outdata.dataSize);
    }
    if (costflag == 0)
        printf("TST_RSA_ENC res %d\n", res);
    outbuf1len = outdata.dataSize;

    rsaEncDecInfo.keyID = tst_sto_asym_priv_key.keyID;
    rsaEncDecInfo.rsa_padding_mode = paddingMode;

    indata.data = outbuf1;
    indata.dataSize = outbuf1len;

    memset(outbuf2, 0, sizeof(outbuf2));
    outdata.data =  outbuf2;
    outdata.dataSize = 1024;

    res = vc_rsa_decrypt(&rsaEncDecInfo, &indata, &outdata);
    if (res == 0 && costflag == 0)
    {
        int i;
        for (i = 0; i < outdata.dataSize; i++)
        {
            printf("0x%02x,", outdata.data[i]);
        }
        printf("##################################vc_rsa_decrypt  %d\n", outdata.dataSize);
    }
    if (costflag == 0)
        printf("TST_RSA_DEC res %d\n", res);
    count ++;

    }
    while (0);//(res == 0);

#if 0
    //export key plain
    vc_except_key expk;
    expk.KeyID = tst_sto_asym_pub_key.keyInfo.keyID;
    expk.trans_mod = TRANS_CIPHER_P_DBG;
    expk.EncInfo = NULL;

    vc_output_info expkey;
    memset(outbuf1, 0, sizeof(outbuf1));
    expkey.data = outbuf1;
    expkey.dataSize = sizeof(outbuf1);
    res = vc_export_key(&expk, &expkey);
    if (res == 0)
        printf("#######exp %d\n%s\n", expk.KeyID, expkey.data);
#endif

   // res = vc_storage_key(&tst_sto_asym_pub_key, 1);
  //  res = vc_storage_key(&tst_sto_asym_priv_key, 1);

    return res;
}

#ifdef SMENABLE
s32 T_sm2_key_compress()
{
    s32 res = 0;

    u8 pub[65] = {0x04,0x60,0xb0,0x99,0x15,0xfa,0x32,0x15,0xbf,0xad,0x2c,0x7a,0x6c,0xa7,0xea,0x09,0xbe,0x1e,0x39,0x88,0x2e,0x40,0x0b,0x66,0xe3,0x24,0xa1,0x55,0xa9,0x1d,0x7f,0x7b,0xae,0xc2,0x05,0x3d,0xf3,0x75,0x8c,0x27,0xf4,0xba,0x9f,0xf2,0x7f,0x52,0x25,0x67,0x17,0x6c,0xf7,0xbf,0xe7,0x7f,0x21,0x89,0xa7,0x4e,0x0b,0x94,0xc1,0xcf,0x84,0xd3,0x4c};
    vc_input_info in;
    in.data = pub;
    in.dataSize = 65;

    u8 outb[40] = {0};
    vc_output_info outdata;
    outdata.data = outb;
    outdata.dataSize = 40;

    res = vc_sm2_get_compress(&in, &outdata);
    printf("sm2 compress %d\n", res);
        {
            int i;
            for (i = 0; i< outdata.dataSize ;i++)
                printf("%02x ", outdata.data[i]);
            printf("############## compressed %d\n", outdata.dataSize);
        }

    u8 outb222[80] = {0};
    vc_output_info outdata222;
    outdata222.data = outb222;
    outdata222.dataSize = 80;
    res = vc_sm2_get_decompress(&outdata, &outdata222);
    printf("sm2 compress222 %d\n", res);
        {
            int i;
            for (i = 0; i< outdata222.dataSize ;i++)
                printf("%02x ", outdata222.data[i]);
            printf("##############222 compressed %d\n", outdata222.dataSize);
        }

}

s32 T_genSM2_tmp_export_get_crt_req()
{
    s32 res = 0;

    vc_gen_key_st genKeyInfo = {0};
    vc_output_info pubKey, privKey;
    genKeyInfo.keyType = KEY_TYPE_SM2_PUB;

    memset(outbuf1, 0, sizeof(outbuf1));
    memset(outbuf2, 0, sizeof(outbuf2));
    privKey.data = outbuf1;
    pubKey.data = outbuf2;
    privKey.dataSize = sizeof(outbuf1);
    pubKey.dataSize = sizeof(outbuf2);

    res = vc_asym_genkey(&genKeyInfo , &pubKey, &privKey);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", pubKey.data);
        printf("##################################vc_asym_genkey  pub %d\n", pubKey.dataSize);
    }

    if (costflag == 0)
        printf("TST_RSA_DEC res %d\n", res);
    if (res == 0 && costflag == 0)
    {
        printf("%s\n", privKey.data);
        printf("##################################vc_asym_genkey  priv %d\n", privKey.dataSize);
    }
    if (costflag == 0)
        printf("TST_GEN_KEY res %d\n", res);

    memset(&tst_sto_asym_pub_key, 0 ,sizeof(tst_sto_asym_pub_key));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(tst_sto_asym_priv_key));

    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_SM2_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_tmp_key(&tst_sto_asym_pub_key);

    printf("sto pub %d\n", res);

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_SM2_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_tmp_key(&tst_sto_asym_priv_key);

    printf("sto priv %d\n", res);


    vc_input_info indata;
    indata.data = tst_dec_data3;
    indata.dataSize = 200;

    vc_output_info outdata;

    memset(outbuf1, 0, sizeof(outbuf1));
    outdata.data =  outbuf1;
    outdata.dataSize = 2048;

    vc_except_key_st encinfo = {0};
    encinfo.KeyID = tst_sto_asym_pub_key.keyID;


    u8 expkbuf[2048] = {0};
    vc_output_info expk = {0};
    expk.data = expkbuf;
    expk.dataSize = sizeof(expkbuf);
    res = vc_export_tmp_key(&encinfo, &expk);
    printf("####################### eeeeexxxxpppppp\n");
    printf("%s\n", expk.data);
    printf("##################################eeeeeeexxxxxppp   pub %d\n", expk.dataSize);

    return res;
}

s32 T_exp_sm2()
{
    int res = 0;
    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CBC;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;//PKCS7_PADDING;


    aesEncDecInfo.keyID = 3;

    vc_except_key_st exceptKeyInfo;
    exceptKeyInfo.EncInfo = (void *)&aesEncDecInfo;
    exceptKeyInfo.KeyID = 1;//public key id
    exceptKeyInfo.trans_mod = TRANS_CIPHER_AES;
   // exceptKeyInfo.

    vc_output_info pubkeyEnc;
    //vc_output_info pubkeyDec;
    unsigned char outbuf[1024] = {0x00};
    pubkeyEnc.data =  outbuf;
    pubkeyEnc.dataSize = 1024;

    res = vc_export_key(&exceptKeyInfo,&pubkeyEnc);
    if (res == 0)
    {
        int i;
        for (i = 0 ; i < pubkeyEnc.dataSize ;i++)
            printf("%02x ", pubkeyEnc.data[i]);
    }
    printf("export  %d\n",res);

    return res;
}
#endif

s32 t_get_info(vc_output_info *out)
{
    s32 res = 0;

    if (out  == NULL || out->data == NULL)
        return -1;

    if (out->dataSize < 32)
        return -2;

    s32 i;
    for (i = 0 ; i < 32; i++)
        out->data[i] = i;

    out->dataSize = 32;

    return res;
}

s32 t_get_info2(vc_output_info *out) // error num
{
    s32 res = 0;

    if (out  == NULL || out->data == NULL)
        return -1;

    if (out->dataSize < 32)
        return -2;

    s32 i;
    for (i = 0 ; i < 32; i++)
        out->data[i] = i+1;

    out->dataSize = 32;

    return res;
}


typedef s32 (*f_init_so)(vc_get_info , vc_output_info* );
s32 TST_INIT_SO()
{
    s32 res = 0;

    void* handle = dlopen("./libinitso.so", RTLD_LAZY);
    if (handle == NULL)
        return -1;

    f_init_so f_init = (f_init_so)dlsym(handle, "init_so");

    u8 outbuf[64]  = {0};
    vc_output_info out;
    out.data = outbuf;
    out.dataSize = 64;

    res = f_init(t_get_info, &out);
    if (res != 0)
    {
        printf("init error %d\n",res);
        goto exit;
    }
    printf("TST_INIT_SO %d\n", res);

exit:
    dlclose(handle);
    return res;
}

s32 TST_DELETE_LIB()
{
    return vc_delete_initso("./libinitso.so");
}

s32 TST_INIT()
{
    s32 res = 0;

    u8 outbuf[64]  = {0};
    vc_output_info out;
    out.data = outbuf;
    out.dataSize = 64;

    res = vc_init(t_get_info ,&out);

    return res;
}

void COST_TEST(int (*func)(void))
{
    clock_t start, finish;
    double cost_time;

    s32 count = 100;
    costflag = 1;
    costcount = 0;
    start = clock();
    s32 res = 0;
    while(count --)
    {
        res = func();
        if (res != 0)
        {
            printf("eeeeee %d\n",res);
            break;
        }
        costcount ++;
    }
    finish = clock();
    cost_time = (double)(finish - start) / CLOCKS_PER_SEC;

    printf("cost %0.2f ms\n", cost_time);
    costflag = 0;
}

typedef struct st_case {
    int id;
    char * name;
    int (*func)(void);
}st_case;

static st_case allCase[] = {
    0, "TST_INIT " ,&TST_INIT,
    0, "TST_AES_GEN_STO_ENC_DEC_MOD", &TST_AES_GEN_STO_ENC_DEC_MOD,
    0, "TST_AES_GEN_STO_ENC_DEC_gcm", &TST_AES_GEN_STO_ENC_DEC_gcm,
    #ifdef SMENABLE
    0, "TST_SM4_GEN_STO_ENC_DEC_cbc", &TST_SM4_GEN_STO_ENC_DEC_cbc,
    #endif
    0, "TST_RSA_GEN_STO_ENC_DEC", &TST_RSA_GEN_STO_ENC_DEC,
    0, "TST_RSA_SIGN and TST_RSA_VERIFY", &TST_RSA_SIGN,
    1000 + 5, "TST_RSA_VERIFY", &TST_RSA_VERIFY,
    0, "TST_RSA_SIGN_file and TST_RSA_VERIFY_file", TST_RSA_SIGN_file,
    1000 + 6, "TST_RSA_VERIFY_file", &TST_RSA_VERIFY_file,
    #ifdef SMENABLE
    0, "TST_SM2_GEN_STO_ENC_DEC", &TST_SM2_GEN_STO_ENC_DEC,
    0, "TST_SM2_SIGN and TST_SM2_VERIFY", &TST_SM2_SIGN,
    1000 +8, "TST_SM2_VERIFY", &TST_SM2_VERIFY,
    #endif
    0, "TST_ECC_GEN_STO_SIG_VEF", &TST_ECC_GEN_STO_SIG_VEF,
    0, "TST_ECDH_25519", &TST_ECDH_25519,
    0, "TST_GET_RANDOM", &TST_GET_RANDOM,
    0, "TST_CALCHMAC", &TST_CALCHMAC,
    0, "TST_CALCCMAC", &TST_CALCCMAC,
    0, "TST_BASE64_ENCODE and TST_BASE64_DECODE", &TST_BASE64_ENCODE,
    1000 + 14, "TST_BASE64_DECODE", &TST_BASE64_DECODE,
    0, "TST_HASH  (and file)", &TST_HASH,
    0, "TST_STO_DEC_PARSE_CRT_KEY", &TST_STO_DEC_PARSE_CRT_KEY,
    0, "TST_VER_CRT", &TST_VER_CRT,
    0, "TST_GEN_CSR (need rsa key (run 4 first))", &TST_GEN_CSR,
    0, "TST_ECC_GEN_ENC_DEC", &TST_ECC_GEN_ENC_DEC,
    0, "TST_ENVELOPE_SEAL_OPEN and ", &TST_ENVELOPE_SEAL_OPEN,

    0, "TST_AES_TMP_GEN_STO_ENC_DEC_MOD", &TST_AES_TMP_GEN_STO_ENC_DEC_MOD,
    0, "TST_RSA_TMP_GEN_STO_ENC_DEC", &TST_RSA_TMP_GEN_STO_ENC_DEC,
    #ifdef SMENABLE
    0, "T_genSM2_tmp_export_get_crt_req", &T_genSM2_tmp_export_get_crt_req,
    0, "T_sm2_key_compress", &T_sm2_key_compress,
    0, "T_exp_sm2", &T_exp_sm2,
    #endif
    // 21, "TST_WB_data", &TST_WB_data,
  //  22, "TST_WB_data2 (file)", &TST_WB_data2,
    };


//#define AUTOTEST
int main()
{
    int ret = 0;

    ret = TST_INIT_SO();
    if (ret != 0)
        return -1;

    int count = 0;
    int allNum = sizeof(allCase)/sizeof(allCase[0]);
    int caseNum = allNum;
    printf("soft_crypto test: 0 is exit\n");
    printf("某些测试需要特定文件或密钥, 密钥ID存在时，无法重复生成。\n");

    int i,j;
    for (i = 0, j =1; i < allNum; i++)
    {
        if (allCase[i].id > 1000)
        {
            allCase[i].id = j - 1 + 1000;
            caseNum --;
        }
        else
        {
            allCase[i].id = j;
            j++;
        }
        //printf("%s %d\n", allCase[i].name, allCase[i].id);
    }

    int num = 0;
    while(1)
    {
        ret = -1;
        printf("***********************************************\n");
        for (i = 0; i < allNum; i++)
        {
            if (allCase[i].id < 1000)
                printf("%d: %s\n",allCase[i].id, allCase[i].name);
        }
        printf("测试项：");
        #ifdef AUTOTEST
            num %= caseNum;
            num ++;
        #else
            scanf("%d", &num);
        #endif


        if (num <= 0 || num > caseNum)
            break;

        for (i = 0; i < allNum; i++)
        {
            if (num == allCase[i].id)
            {
                ret = allCase[i].func();
                printf("%s ret %d\n", allCase[i].name, ret);
                printf("-------- %d %d\n",i, allCase[i+1].id);
                if ((i <= caseNum - 1) && allCase[i+1].id > 1000 )
                {
                    ret = allCase[i+1].func();
                    printf("%s ret %d\n", allCase[i].name, ret);
                    break;
                }
            }
        }
        if (ret != 0)
        {
            printf("eeeeeeeeeeeeeeeeeeeeeeeee %d\n", num);
            break;
        }
    }

/*********************xx times run xxx***************************/
    //COST_TEST(&TST_ECC_GEN_ENC_DEC);
    //COST_TEST(&TST_RSA_GEN_STO_ENC_DEC);
    //COST_TEST(&TST_ECC_GEN_STO_SIG_VEF);
/*****************************************************************/

   // TST_DELETE_LIB();
    return 0;
}
