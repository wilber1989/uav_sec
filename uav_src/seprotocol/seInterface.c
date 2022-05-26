#include "platformInfo.h"
#include "vc_sw_crypt_service.h"
#include <dlfcn.h>
#include "seInterface.h"
#include "openssl/ossl_typ.h"
#include "openssl/asn1.h"
#include <string.h>
#include <errno.h>

static unsigned char outbuf1[4096];
static int outbuf1len;
static unsigned char outbuf2[4096];
static int outbuf2len;

vc_storage_key_st tst_sto_asym_pub_key;
vc_storage_key_st tst_sto_asym_priv_key;
u8 keymac[32] = {0};
u8 keymac2[32] = {0};
static unsigned char tst_iv[16] = {0};

//static u8 mac[32] ={0};
static u8 deviceID[32] = {0x00};
static u32 deviceID_len = 32;


//#define EXPORT_AES_KEY_ID 3
//#define GEN_RSA_PUBLIC_KEY_ID 1
//#define GEN_RSA_PRIVATE_KEY_ID 2
//#define STORAGE_RSA_CERT_FILE_ID 1
//#define STORAGE_RSA_PRIVATE_FILE_ID 2
//static s32 mExport_aes_key_id;
//static s32 mRsa_public_key_id;
//static s32 mRsa_private_key_id;
//static s32 mStorage_rsa_cert_file_id;
//static s32 mStorage_rsa_private_file_id;


#define FILE_DIR_PATH "./"
#define I_MAC_FILE_NAME "I_MAC"
#define PUBLIC_KEY_FILE_NAME "KEY_1"
#define PRIVATE_KEY_FILE_NAME "KEY_2"
#define AES_KEY_FILE_NAME "KEY_3"
#define STORAGE_CERT_FILE_NAME "CRT_1"
#define STORAGE_PRIVATE_KEY_FILE_NAME "CRT_2"

#define STORAGE_CA_CERT_FILE_NAME "CRT_3"
#define STORAGE_CRL_CERT_FILE_NAME "CRT_4"
#define STORAGE_KEYID_AND_MAC "KEYID_AND_MAC.txt"

#define LIB_INIT_SO_PATH FILE_DIR_PATH "lib/libinitso.so"


#define FILE_PATH_MAX_LEN 256

#define DEFAULT_SUBJECT_INFO "CN=Device cert,OU=IOT,O=CMCC,L=CD,ST=SC,C=CN"//CN填充device id





KeyAndMacNode *keyAndMacList = NULL;

s32 deleteFIle(u8 * FileName)
{
    s32 ret = -1;
    u8 filepath[128] = {0x00};
    sprintf(filepath,"%s%s",FILE_DIR_PATH,FileName);
    FILE * fp = fopen(filepath,"r");
    if(fp != NULL)
    {
        fclose(fp);
        ret = remove(filepath);
        if(ret != 0)
        {
            V2X_VECENT_PRINTF("delete failed remove %s Message:%s\n" ,filepath, strerror(errno));
        }
    }
    return ret;
}

void deleteAllKeyAndCert()
{

    //delete KEY file
    //delete Cert file
    //delete KEYID_AND_MAC.txt file
    //delete I_MAC file
    deleteFIle(PUBLIC_KEY_FILE_NAME);
    deleteFIle(PRIVATE_KEY_FILE_NAME);
    deleteFIle(AES_KEY_FILE_NAME);
    deleteFIle(STORAGE_CERT_FILE_NAME);
    deleteFIle(STORAGE_PRIVATE_KEY_FILE_NAME);
    deleteFIle(STORAGE_KEYID_AND_MAC);
    deleteFIle(I_MAC_FILE_NAME);

}

s32 t_set_deviceid_into(vc_input_info *input)
{
    s32 res = -1;
    if(input->dataSize<=32&&input->dataSize>0)
    {
        memcpy(deviceID,input->data,input->dataSize);
        deviceID_len = input->dataSize;
        res = 0;
    }
    else if(input->dataSize>32)
    {
        V2X_VECENT_PRINTF("deviceID len is large");
        res = -1;
    }
    else 
    {
        V2X_VECENT_PRINTF("deviceID len is error");
        res = -2;
    } 
    return res;
}

s32 t_get_deviceid_info(vc_output_info *out)//应该直接返回deviceID,
{
    s32 res = 0;

    if (out  == NULL || out->data == NULL)
        return -1;

    if (out->dataSize < 32)
        return -2;

    if(deviceID_len>32)
    {
        V2X_VECENT_PRINTF("t_get_info deviceID_len is large");
        return -3;
    }
    else if(deviceID_len<=0)
    {
        V2X_VECENT_PRINTF("t_get_info deviceID_len is small");
        return -4;
    }
    else
    {
        memcpy(out->data,deviceID,deviceID_len);
        out->dataSize = deviceID_len;
        res = 0;
    }
    return res;
}

//#define USE_DL_OPEN_INIT_SO
#ifndef USE_DL_OPEN_INIT_SO
s32 TST_INIT_SO()
{
    s32 res = 0;
    u8 outbuf[64]  = {0};
    vc_output_info out;
    out.data = outbuf;
    out.dataSize = 64;
    res = init_so(t_get_deviceid_info, &out);
    if (res != 0)
    {
        V2X_VECENT_PRINTF("init error %d\n",res);
    }
    return res;
}

#else
typedef s32 (*f_init_so)(vc_get_info , vc_output_info* );
s32 TST_INIT_SO()
{
    s32 res = 0;

    void* handle = dlopen(LIB_INIT_SO_PATH, RTLD_LAZY);
    if (handle == NULL)
    {
        V2X_VECENT_PRINTF("TST_INIT_SO handle == NULL \n");
        return -1;
    }
    f_init_so f_init = (f_init_so)dlsym(handle, "init_so");
    u8 outbuf[64]  = {0};
    vc_output_info out;
    out.data = outbuf;
    out.dataSize = 64;
    res = f_init(t_get_deviceid_info, &out);
    if (res != 0)
    {
        V2X_VECENT_PRINTF("init error %d\n",res);
        goto exit;
    }


exit:
    dlclose(handle);
    if(res == 0)
      // remove(LIB_INIT_SO_PATH);
    return res;
}
#endif

s32 TST_INIT()
{
    s32 res = 0;

    u8 outbuf[64]  = {0};
    vc_output_info out;
    out.data = outbuf;
    out.dataSize = 64;

    res = vc_init(t_get_deviceid_info ,&out);

    return res;
}


int TST_RSA_GEN_STO_ENC_DEC()
{
    int res = 0;
    res = isRSAKeyExist();
    if(res != KEY_IS_NOT_EXIST)
        return 0;
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
    
    if (res != 0 )
    {
        V2X_VECENT_PRINTF("vc_asym_genkey error");
        return res;
    }
    
   // vc_storage_key_info storageKeyInfo;
    memset(&tst_sto_asym_pub_key, 0 ,sizeof(vc_storage_key_st));
    memset(&tst_sto_asym_priv_key, 0 ,sizeof(vc_storage_key_st));
    
    tst_sto_asym_pub_key.keyMac = keymac;
    tst_sto_asym_pub_key.keyType = KEY_TYPE_RSA_PUB;

    tst_sto_asym_pub_key.keyData.data = pubKey.data;
    tst_sto_asym_pub_key.keyData.dataSize = pubKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_pub_key);
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_KEY_TYPE_RSA_PUB,tst_sto_asym_pub_key.keyID,KEY_TYPE_RSA_PUB,tst_sto_asym_pub_key.keyMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save tst_sto_asym_pub_key error");
            return res;
        }
    }
    else
    {
       V2X_VECENT_PRINTF("TST_RSA_GEN_STO_ENC_DEC save tst_sto_asym_pub_key error");
    }
    

    //vc_storage_key_info storageKeyInfo2;

    tst_sto_asym_priv_key.keyMac = keymac2;
    tst_sto_asym_priv_key.keyType = KEY_TYPE_RSA_PRIV;

    tst_sto_asym_priv_key.keyData.data = privKey.data;
    tst_sto_asym_priv_key.keyData.dataSize = privKey.dataSize;

    res = vc_storage_key(&tst_sto_asym_priv_key);
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_KEY_TYPE_RSA_PRIV,tst_sto_asym_priv_key.keyID,KEY_TYPE_RSA_PRIV,tst_sto_asym_priv_key.keyMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save tst_sto_asym_priv_key error");
        }
    }
    else
    {
       V2X_VECENT_PRINTF("TST_RSA_GEN_STO_ENC_DEC save tst_sto_asym_priv_key error");
    }

    return res;
}


//0 is exist
s32 isRSAKeyExist()
{
    return getKeyIDForKeyUse(FILE_KEY_TYPE_RSA_PRIV);
}

s32 isMACKeyExist()
{
    FILE *fp = NULL;
    u8 filepath[FILE_PATH_MAX_LEN] = {0x00};
    sprintf(filepath,"%s%s",FILE_DIR_PATH,I_MAC_FILE_NAME);
    fp = fopen(filepath,"r");
    if(fp == NULL)
    {
        return -1;
    }
    fclose(fp);
    return 0;
}


s32 genRsaDeviceKeyPair()
{
    int ret  = 0;
    ret  = TST_INIT();
    if(ret != 0)
    {
        V2X_VECENT_PRINTF("TST_INIT %d\n", ret);
        return -1;
    }

    ret = TST_AES_GEN_STO_ENC_DEC_MOD();
    if(ret !=0 )
    {
        V2X_VECENT_PRINTF("TST_AES_GEN_STO_ENC_DEC_MOD error no = %d\n",ret);
        return ret; 
    }

    ret = TST_RSA_GEN_STO_ENC_DEC();
    if(ret != 0)
    {
        V2X_VECENT_PRINTF("TST_RSA_GEN_STO_ENC_DEC error no = %d\n",ret);
        return -1;
    }


    return 0;
}

//key_type = FILE_KEY_TYPE_AES
s32 isAesKeyExist()
{
    return getKeyIDForKeyUse(FILE_KEY_TYPE_AES);
}

s32 TST_AES_GEN_STO_ENC_DEC_MOD()
{
    s32 res = 0;
    if(isAesKeyExist() != KEY_IS_NOT_EXIST)
    {
        return 0;
    }
    vc_gen_key_st genKeyInfo = {0};
    vc_output_info aesKeyInfo;
    genKeyInfo.keyLen = 16;
    genKeyInfo.keyType = KEY_TYPE_AES;
    u8 mac[32] ={0};


    memset(outbuf1, 0, sizeof(outbuf1));
    aesKeyInfo.data = outbuf1;

    res = vc_sym_genkey(&genKeyInfo , &aesKeyInfo);
    if (res != 0)
    {
        V2X_VECENT_PRINTF("vc_sym_genkey error ");
        return res;
    }


    vc_storage_key_st storageKeyInfo = {0};

    //storageKeyInfo.isWhiteBoxEnc = 0;
    storageKeyInfo.keyMac = mac;
    storageKeyInfo.keyType = genKeyInfo.keyType;
    storageKeyInfo.keyData.data = aesKeyInfo.data;
    storageKeyInfo.keyData.dataSize = aesKeyInfo.dataSize;

    res = vc_storage_key(&storageKeyInfo);
    if(res!=0)
    {
        V2X_VECENT_PRINTF("vc_storage_key error ,sto key %d,aes key_id = %d\n", res, storageKeyInfo.keyID);
    }
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_KEY_TYPE_AES,storageKeyInfo.keyID,KEY_TYPE_AES,storageKeyInfo.keyMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save storageKeyInfo error");
        }
    }
    return res;
}


int getpublicKey(vc_output_info *pubkeyDec)
{
    int res = 0;
    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CBC;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;//PKCS7_PADDING;


    aesEncDecInfo.keyID = getKeyIDForKeyUse(FILE_KEY_TYPE_AES)&0xff;
    if(aesEncDecInfo.keyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("aesEncDecInfo.keyID == KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }

    vc_except_key_st exceptKeyInfo;
    exceptKeyInfo.EncInfo = (void *)&aesEncDecInfo;
    exceptKeyInfo.KeyID = getKeyIDForKeyUse(FILE_KEY_TYPE_RSA_PUB)&0xff;
    if(exceptKeyInfo.KeyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("FILE_KEY_TYPE_RSA_PUB KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }
    exceptKeyInfo.trans_mod = TRANS_CIPHER_AES;
   // exceptKeyInfo.
    u32 tst_enc_data2[1024];

    vc_input_info indata;

    vc_output_info pubkeyEnc;
    //vc_output_info pubkeyDec;
    unsigned char outbuf[1024] = {0x00};
    pubkeyEnc.data =  outbuf;
    pubkeyEnc.dataSize = 1024;

    res = vc_export_key(&exceptKeyInfo,&pubkeyEnc);


    memset(tst_iv,0,16);

    aesEncDecInfo.keyID = getKeyIDForKeyUse(FILE_KEY_TYPE_AES)&0xff;
    if(aesEncDecInfo.keyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("aesEncDecInfo.keyID == KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }
    indata.data = outbuf;
    indata.dataSize = pubkeyEnc.dataSize;

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, pubkeyDec);
    if (res != 0)
    {
        V2X_VECENT_PRINTF("vc_aes_decrypt error res %d\n", res);
    }

exit:
    return res;
}


int getprivateKey(vc_output_info *prikeyDec)
{
    int res = 0;
    vc_aes_encdec_st aesEncDecInfo = {0};
    aesEncDecInfo.aes_enc_mode = AES_ENC_CBC;//AES_ENC_CBC;
    memset(tst_iv,0,16);
    aesEncDecInfo.iv = tst_iv;
    aesEncDecInfo.aes_padding_mode = PKCS7_PADDING;//PKCS7_PADDING;


    aesEncDecInfo.keyID  = getKeyIDForKeyUse(FILE_KEY_TYPE_AES)&0xff;
    if(aesEncDecInfo.keyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("aesEncDecInfo.keyID == KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }
    vc_except_key_st exceptKeyInfo;
    exceptKeyInfo.EncInfo = (void *)&aesEncDecInfo;
    exceptKeyInfo.KeyID = getKeyIDForKeyUse(FILE_KEY_TYPE_RSA_PRIV)&0xff;
    if(exceptKeyInfo.KeyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("FILE_KEY_TYPE_RSA_PRIV KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }
    exceptKeyInfo.trans_mod = TRANS_CIPHER_AES;
   // exceptKeyInfo.
 
    vc_input_info indata;

    vc_output_info prikeyEnc;
    //vc_output_info pubkeyDec;
    unsigned char outbuf[2048] = {0x00};
    prikeyEnc.data =  outbuf;
    prikeyEnc.dataSize = 2048;

    res = vc_export_key(&exceptKeyInfo,&prikeyEnc);
    if(res!=0)
    {
        V2X_VECENT_PRINTF("getprivateKey vc_export_key res %d\n", res);
        return res;
    }


    memset(tst_iv,0,16);

    aesEncDecInfo.keyID = getKeyIDForKeyUse(FILE_KEY_TYPE_AES)&0xff;
    if(aesEncDecInfo.keyID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("aesEncDecInfo.keyID == KEY_IS_NOT_EXIST,error");
        res = -1;
        goto exit;
    }
    indata.data = outbuf;
    indata.dataSize = prikeyEnc.dataSize;

    res = vc_aes_decrypt(&aesEncDecInfo, &indata, prikeyDec);
    if (res != 0)
    {
        V2X_VECENT_PRINTF("vc_aes_decrypt erro res %d\n", res);
    }
exit:
    return res;
}


s32 TST_HASH(vc_input_info *indata,vc_output_info *outdata)
{
    s32 res = 0;
    vc_hash_st hashInfo;
    hashInfo.hash_type = HASH_MD_SHA256;//HASH_SM3;

    res = vc_hash(&hashInfo, indata, outdata);
    if(res !=0 )
    {
        V2X_VECENT_PRINTF("TST_HASH error res %d\n", res);
    }
    return res;
}


/**
**initSourceInfo 设置设备ID，初始化I_MAC和AES加密密钥,程序初始化必调一次
**/
s32 initSourceInfo(vc_input_info *input)
{
    s32 res = -1;
    res = t_set_deviceid_into(input);
    if(res != 0)
    {
        return res;
    }

    res = isMACKeyExist();
    if(res != 0)
    {
        res = TST_INIT_SO();
        if(res != 0)
        {
            return res;
        }
    }

    res = TST_INIT();
    if(res != 0)
    {
        V2X_VECENT_PRINTF("TST_INIT failed ,res = %d",res);
    }

    if(isKeyAndMacFileExist()==0)
    {
        res = readKeyIdAndMacFromFile();
    }

    return res;
}

s32 storageDeviceCrt(vc_input_info *inputInfo)
{
    s32 res = 0;
    vc_storage_crt_st storageCrtInfo = {0};
    u8 mac[32] = {0};
    memset(outbuf1,0,sizeof(outbuf1));
    storageCrtInfo.crtData.data = outbuf1;
    storageCrtInfo.crtData.dataSize = sizeof(outbuf1);
    storageCrtInfo.crtMac = mac;
    storageCrtInfo.isWhiteBoxEnc = 0;

    storageCrtInfo.crtData.data = inputInfo->data;
    storageCrtInfo.crtData.dataSize = inputInfo->dataSize;

    res = vc_storage_crt(&storageCrtInfo);
    if(res != 0)
    {
        V2X_VECENT_PRINTF("vc_storage_crt is failed,res = %d",res);
    }
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_TYPE_RSA_CRT,storageCrtInfo.crtID,0x20,storageCrtInfo.crtMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save storageKeyInfo error");
        }
    }
}


s32 storageCrlListCrt(vc_input_info *crlList_info)
{
    vc_storage_crt_st storageCrtInfo = {0x00};
    s32 res = -1;
    u8 mac[32] = {0x00};
    storageCrtInfo.crtData.data = crlList_info->data;
    storageCrtInfo.isWhiteBoxEnc = 0;
    storageCrtInfo.crtData.dataSize = crlList_info->dataSize + 1;
    if(isCrlCertFileExist()==KEY_IS_NOT_EXIST)
    {
        storageCrtInfo.crtID = 0;
        storageCrtInfo.crtMac = mac;
    }
    else
    {
        KeyAndMacNode *keyMacNode;
        storageCrtInfo.crtID = getKeyInfoForKeyUse(FILE_TYPE_CRLLIST,&keyMacNode)&0xff;
        storageCrtInfo.crtMac = keyMacNode->data+3;
    }

    res = vc_storage_crt(&storageCrtInfo);
    if(res != 0)
    {
       V2X_VECENT_PRINTF("vc_storage_crt is failed,res = %d",res);
    }
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_TYPE_CRLLIST,storageCrtInfo.crtID,0x20,storageCrtInfo.crtMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save storageKeyInfo error");
        }
    }
    return res;
}

s32 storageKeyFile()
{
    s32 res = 0;
    vc_storage_crt_st storageCrtInfo = {0};
    u8 mac[32] = {0};

    vc_input_info prikeyDec;
    memset(outbuf2,0,sizeof(outbuf2));
    prikeyDec.data = outbuf2;
    prikeyDec.dataSize = sizeof(outbuf2);

    res = getprivateKey((vc_output_info *)&prikeyDec);
    if(res != 0)
    {
        V2X_VECENT_PRINTF("getprivateKey is failed ,res = %d",res);
        return res;
    }

    memset(outbuf1,0,sizeof(outbuf1));
    storageCrtInfo.crtData.data = outbuf1;
    storageCrtInfo.crtData.dataSize = sizeof(outbuf1);
    storageCrtInfo.crtMac = mac;
    storageCrtInfo.isWhiteBoxEnc = 0;

    storageCrtInfo.crtData.dataSize = prikeyDec.dataSize + 1;
    memcpy(storageCrtInfo.crtData.data,prikeyDec.data,prikeyDec.dataSize);
    res = vc_storage_crt(&storageCrtInfo);
    if(res != 0)
    {
        V2X_VECENT_PRINTF("vc_storage_crt is failed ,res = %d", res);
    }

    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_TYPE_RSA_PRI,storageCrtInfo.crtID,0x20,storageCrtInfo.crtMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save storageKeyInfo error");
        }
    }
    return res;
}


s32 storageCaCertFile(vc_input_info *ca_cert_info)
{
    vc_storage_crt_st storageCrtInfo = {0x00};
    s32 res = -1;
    u8 mac[32] = {0x00};
    storageCrtInfo.crtData.data = ca_cert_info->data;
    storageCrtInfo.isWhiteBoxEnc = 0;
    storageCrtInfo.crtData.dataSize = ca_cert_info->dataSize + 1;
    storageCrtInfo.crtID = 0;
    storageCrtInfo.crtMac = mac;
    res = vc_storage_crt(&storageCrtInfo);
    if(res != 0)
    {
       V2X_VECENT_PRINTF("vc_storage_crt ca is failed,res = %d",res);
    }
    if(res == 0)
    {
        res = updateKeyAndMacListAndFile(FILE_TYPE_CA,storageCrtInfo.crtID,0x20,storageCrtInfo.crtMac);
        if(res !=0)
        {
            V2X_VECENT_PRINTF("updateKeyAndMacListAndFile save storageKeyInfo error");
        }
    }

    return res;
}


s32 isCaCertFileExist()
{
    return getKeyIDForKeyUse(FILE_TYPE_CA);
}

s32 isDeviceCertFileExist()
{
    return getKeyIDForKeyUse(FILE_TYPE_RSA_CRT);
}


s32 isCrlCertFileExist()
{
    return getKeyIDForKeyUse(FILE_TYPE_CRLLIST);
}

s32 isPrivateKeyFileExist()
{
    return getKeyIDForKeyUse(FILE_TYPE_RSA_PRI);
}


/*
*
*优先存证书，保证证书文件ID为1，再存私钥文件，保证私钥文件ID为2;
*/

s32 storageCertAndKeyFile(vc_input_info *inputInfo)
{
    s32 res = 0;
    if(isDeviceCertFileExist()!=0)
    {
        res = storageDeviceCrt(inputInfo);
        if(res != 0)
        {
            return res;
        }
    }
    if(isPrivateKeyFileExist()!=0)
    {
        res = storageKeyFile();
    }


    return res;
}

s32 exportFileCert(vc_output_info* outputInfo)
{
    s32 res = 0;
    vc_except_crt_st crtInfo;
    crtInfo.crtID = getKeyIDForKeyUse(FILE_TYPE_RSA_CRT)&0xff;
    if(crtInfo.crtID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("FILE_TYPE_RSA_CRT == KEY_IS_NOT_EXIST,error");
        res = -1;
        return  res;
    }
    res = vc_export_crt(&crtInfo,outputInfo);
    return res;
}

s32 exportCrlListFileCert(vc_output_info* outputInfo)
{
    s32 res = 0;
    vc_except_crt_st crtInfo;
    crtInfo.crtID = getKeyIDForKeyUse(FILE_TYPE_CRLLIST)&0xff;
    if(crtInfo.crtID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("FILE_TYPE_CRLLIST == KEY_IS_NOT_EXIST,error");
        res = -1;
        return  res;
    }
    res = vc_export_crt(&crtInfo,outputInfo);
    return res;
}

s32 exportFileKey(vc_output_info* outputInfo)
{
    s32 res = 0;
    vc_except_crt_st crtInfo;
    crtInfo.crtID = getKeyIDForKeyUse(FILE_TYPE_RSA_PRI)&0xff;
    if(crtInfo.crtID == KEY_IS_NOT_EXIST&0xff)
    {
        V2X_VECENT_PRINTF("FILE_TYPE_RSA_PRI == KEY_IS_NOT_EXIST,error");
        res = -1;
        return  res;
    }
    res = vc_export_crt(&crtInfo,outputInfo);
    return res;
}



s32 deleteFileKeyOrFIleCrt(vc_key_use_type keyUseType)
{
    s32 res = -1;

    KeyAndMacNode * keyInfo;
    res = getKeyInfoForKeyUse(keyUseType,&keyInfo);
    if(res != -1)
    {
        vc_storage_crt_st storageKeyInfo = {0x00};
        storageKeyInfo.crtID = keyInfo->data[1];
        storageKeyInfo.crtMac = keyInfo->data+3;
        res = vc_delete_crt(&storageKeyInfo);
    }
}


/**
证书SUBJECT
CN = 作用，比如CA，root CA
OU = CA，部门
O = CA，组织，单位名称
L = CQ，市
ST = CQ，省
C = CN，国家
example "CN=device cert,OU=IOT,O=CMCC,L=CD,ST=SC,C=CN";
**/
s32 GEN_CSR(vc_input_info *subjectInfo,vc_output_info * output_csr_data_info)
{
    s32 res = 0;
    vc_csr_st csr;
    u8 subject_name[128] = {0x00};
    s32 subject_len = 128;


    if(subjectInfo == NULL)
    {
        memcpy(subject_name,DEFAULT_SUBJECT_INFO,strlen(DEFAULT_SUBJECT_INFO));
        subject_len = strlen(DEFAULT_SUBJECT_INFO);
    }
    else
    {
        memcpy(subject_name,subjectInfo->data,subjectInfo->dataSize);
        subject_len = subjectInfo->dataSize;
    }
    

    csr.hashAlg = HASH_MD_SHA256;
    csr.keyID = getKeyIDForKeyUse(FILE_KEY_TYPE_RSA_PRIV)&0xff;
    if(csr.keyID == (KEY_IS_NOT_EXIST&0xff))
    {
        V2X_VECENT_PRINTF("csr.keyID  get FILE_KEY_TYPE_RSA_PRIV eroor, KEY_IS_NOT_EXIST");
        return -1;
    }
    csr.key_usage = 0;
    csr.ns_cert_type = 0;
    csr.subject_name = subject_name;

    vc_output_info output_csr_info;
    uint8_t tmp_csr_buf[2048] = {0x00};
    uint32_t tmp_csr_buf_len = 2048;
    output_csr_info.data = tmp_csr_buf;
    output_csr_info.dataSize = tmp_csr_buf_len;
    res = vc_gen_csr(&csr, &output_csr_info);
    if(res !=0)
    {
        return res;
    }

    Hex_PRINTF(output_csr_info.data,output_csr_info.dataSize,"HEX:");
    int32_t i = 0;




    uint8_t * str_pos_p = strstr(output_csr_info.data,CSR_START_HEADER_STR);

    uint8_t * end_str_pos_p = strstr(output_csr_info.data,CSR_END_HEADER_STR);

    uint8_t * last_str_pos_p = 0;
    int32_t out_buff_offset = 0;
    if(str_pos_p == NULL)
    {
        V2X_VECENT_PRINTF("not find %s ",CSR_START_HEADER_STR);
        return -1;
    }
    else
    {
        last_str_pos_p = str_pos_p + strlen(CSR_START_HEADER_STR);
    }

    do
    {
        str_pos_p = strstr(last_str_pos_p + strlen(SEPARATOR_FLAG),SEPARATOR_FLAG);
        if(str_pos_p == NULL)
            break;

        memcpy(output_csr_data_info->data + out_buff_offset,last_str_pos_p, str_pos_p - last_str_pos_p);
        out_buff_offset +=  str_pos_p - last_str_pos_p;
        last_str_pos_p = str_pos_p + strlen(SEPARATOR_FLAG);
        if(last_str_pos_p == end_str_pos_p)
            break;
    }
    while (1);
    output_csr_data_info->dataSize = out_buff_offset;
    return 0;
}



s32 vc_verify_crt(vc_input_info *crtInfo, u8 caID, u8 crlID, u8 *cn)
{

}



s32 isKeyAndMacFileExist()
{
    FILE *fp = NULL;
    u8 filepath[FILE_PATH_MAX_LEN] = {0x00};
    sprintf(filepath,"%s%s",FILE_DIR_PATH,STORAGE_KEYID_AND_MAC);
    fp = fopen(filepath,"r");
    if(fp == NULL)
    {
        return -1;
    }
    fclose(fp);
    return 0;
}

//-------------------------------------------
s32 updateKeyIdAndMacFile(u8 * keyMacInfo,s32 keyMacInfoLen)
{
    //(keyMacInfo,keyMacInfoLen,"update src data === ");
    s32 res = 0;
    FILE *fp = NULL; 
    u8 filepath[FILE_PATH_MAX_LEN] = {0x00};
    sprintf(filepath,"%s%s",FILE_DIR_PATH,STORAGE_KEYID_AND_MAC);

    if(keyMacInfo == NULL)
    {
        res = -1;
        goto exit;
    }
    if(isKeyAndMacFileExist()!=0)
    {
        fp = fopen(filepath,"wb+");
        //u8 tmpbuf[NODE_DATA_LEN] = {0x00};
        fwrite(keyMacInfo,keyMacInfoLen,1,fp); 
        fwrite("\n",1,1,fp);
        fflush(fp);
    }
    else
    {
        fp = fopen(filepath,"rb+");
        u8 tmpbuf[NODE_DATA_LEN] = {0x00};
        s32 curpos = 0;
        s32 lastpos = 0;
        long int offset = 0;
        while(fgets(tmpbuf,NODE_DATA_LEN,fp)!=NULL)
        {

            curpos = ftell(fp);
            offset = curpos - lastpos;
            lastpos = curpos;
            if(memcmp(tmpbuf,keyMacInfo,2)==0)
            {
                fseek(fp,offset,SEEK_CUR);
                fwrite(keyMacInfo,keyMacInfoLen,1,fp); 
                fwrite("\n",1,1,fp);
                fflush(fp);
                goto exit;
            }
            memset(tmpbuf,0x00,NODE_DATA_LEN);
        }
        fseek(fp,0L,SEEK_END);
        fwrite(keyMacInfo,keyMacInfoLen,1,fp); 
        fwrite("\n",1,1,fp);
        fflush(fp);
    }
    
exit:
    if(fp!=NULL)
        fclose(fp);
    return res;
}

//--------------------------------------------

s32 updateKeyAndMacList(u8 * keyMacInfo,s32 keyMacInfoLen)
{
    s32 res  = 0;
    s32 is_find_update = 0;
    if(keyAndMacList == NULL)
    {
        KeyAndMacNode *node = malloc(sizeof(KeyAndMacNode));
        if(node == NULL)
        {
            res = -1;
            V2X_VECENT_PRINTF("updateKeyAndMakcList keyAndMacList == NULL malloc failed");
            goto exit;
        }
        memset(node->data,0x00,NODE_DATA_LEN);
        memcpy(node->data,keyMacInfo,keyMacInfoLen);
        node->next = NULL;
        keyAndMacList = node;
    }
    else
    {
        KeyAndMacNode *tmpnode;
        tmpnode = keyAndMacList;
        while(1)
        {
            if(memcmp(tmpnode->data,keyMacInfo,2) == 0)
            {
                memcpy(tmpnode->data,keyMacInfo,keyMacInfoLen);
                is_find_update = 1;
                break;
            }
            if(tmpnode->next == NULL)
            {
                break;
            }
            tmpnode = tmpnode->next;
        }
        if(is_find_update == 0)//add new
        {
            while (tmpnode->next != NULL)
            {
                tmpnode = tmpnode->next;
            }
            KeyAndMacNode *node = malloc(sizeof(KeyAndMacNode));
            if(node == NULL)
            {
                res = -1;
                V2X_VECENT_PRINTF("updateKeyAndMakcList malloc failed");
                goto exit;
            }
            memset(node->data,0x00,NODE_DATA_LEN);
            memcpy(node->data,keyMacInfo,keyMacInfoLen);
            node->next = NULL;
            tmpnode->next = node;
        }
    }
exit:
    return res;
}

//信息结构为keyUse(1byte) | keyID(1byte) |keyType(1byte) |keyMac(32byte)
//如果存储的是证书。则传递keyType 参数传0x20
s32 updateKeyAndMacListAndFile(vc_key_use_type keyUse,u8 keyID,s32 keyType,u8 * keyMac)
{
    s32 res = 0;
    u8 keyMacInfo[NODE_DATA_LEN] = {0x00};
    s32 keyMacInfoLen = 0;

    keyMacInfo[0] = keyUse&0xff;
    keyMacInfoLen+=1;
    keyMacInfo[1] = keyID;
    keyMacInfoLen+=1;
    keyMacInfo[2] = keyType&0xff;
    keyMacInfoLen+=1;
    memcpy(keyMacInfo+keyMacInfoLen,keyMac,32);
    keyMacInfoLen+=32;
    
    res = updateKeyAndMacList(keyMacInfo,keyMacInfoLen);
    if(res == 0)
    {
        res = updateKeyIdAndMacFile(keyMacInfo,keyMacInfoLen);
    }
    
exit:

    return res;
}




static void freeKeyAndMacList()
{
    if(keyAndMacList!=NULL)
    {
        //s32 listLen = 0;
        KeyAndMacNode *tmp_node = keyAndMacList;
        KeyAndMacNode *free_node = NULL;
        
        do
        {
            free_node = tmp_node;
            tmp_node = tmp_node->next;
            if(free_node!= NULL)
            {
                free(free_node);
                free_node = NULL;
            }
        //   listLen++;
        } while (tmp_node!=NULL);

    }
}

s32 readKeyIdAndMacFromFile()
{
    s32 res = 0;
    FILE *fp = NULL;
    u8 filepath[FILE_PATH_MAX_LEN] = {0x00};
    sprintf(filepath,"%s%s",FILE_DIR_PATH,STORAGE_KEYID_AND_MAC);
    if(isKeyAndMacFileExist()!=0)
    {
        keyAndMacList = NULL;
        res = 0;
    }
    else
    {
        fp = fopen(filepath,"rb");
        if (fp == NULL)
        {
            V2X_VECENT_PRINTF("open %s error ",filepath);
            res = -1;
            goto exit;
        }
        u8 *tmp = NULL;
        u8 tmpbuf[NODE_DATA_LEN] = {0x00};
        KeyAndMacNode *tmpnode = NULL;
         

        while(1)
        {
            memset(tmpbuf,0x00,NODE_DATA_LEN);
            tmp = fgets(tmpbuf,NODE_DATA_LEN,fp);
            if(tmp == NULL)
            {
                break;
            }
            KeyAndMacNode *node = malloc(sizeof(KeyAndMacNode));
            if(node == NULL)
            {
                freeKeyAndMacList();
                res = -1;
                goto exit;
            }
      
            memset(node->data,0x00,NODE_DATA_LEN);
            memcpy(node->data,tmpbuf,NODE_DATA_LEN);
            node->next = NULL;

            if(tmpnode != NULL)
            {
                tmpnode->next = node;
            }
	    else
	    {
                tmpnode = node;
	    }
           if(keyAndMacList == NULL)
            {
                //head
                keyAndMacList = tmpnode;
            }
        }
/////////////////////////////////////////////////////
        KeyAndMacNode *tmpnode1;
        tmpnode1 = keyAndMacList;
        while(1)
        {
            Hex_PRINTF(tmpnode1->data,NODE_DATA_LEN,"readKeyIdAndMacFromFile tmpnode: ");
            if(tmpnode1->next == NULL)
                goto exit;
            tmpnode1 = tmpnode1->next;

        }

    }
    
exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    return res;
}

/*
*return keyid,if no this key Id,return -1
*/
s32 getKeyIDForKeyUse(vc_key_use_type keyUse)
{
    s32 res = KEY_IS_NOT_EXIST;
    if(keyAndMacList!=NULL)
    {
        KeyAndMacNode *tmp_node;
        tmp_node = keyAndMacList;
        while(tmp_node!= NULL)
        {
            if(keyUse == tmp_node->data[0])
            {
                Hex_PRINTF(tmp_node->data,37,"find the MAC_data --  DATA : ");
                res = tmp_node->data[1];
                break;
            }
            tmp_node = tmp_node->next;
        }

    }
    V2X_VECEN_DEBUG_PRINTF("getKeyIDForType keyId = %d ,keyUse = %d\n",res,keyUse);
    return res;
}


/*
*return keyid,if no this key Id,return -1
*/
s32 getKeyInfoForKeyUse(vc_key_use_type input_key_use,KeyAndMacNode **keyInfo)
{
    s32 res = KEY_IS_NOT_EXIST;
    if(keyAndMacList!=NULL)
    {
        KeyAndMacNode *tmp_node;
        tmp_node = keyAndMacList;
        while(tmp_node != NULL)
        {
            if(input_key_use == tmp_node->data[0])
            {
                res = tmp_node->data[1];
                *keyInfo = tmp_node;
                break;
            }
            tmp_node = tmp_node->next;
        }

    }
    return res;
}
