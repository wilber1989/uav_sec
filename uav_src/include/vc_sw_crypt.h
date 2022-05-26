#ifndef __VC_SW_CRYPT_H__
#define __VC_SW_CRYPT_H__

#include "vecent_se_platform_info.h"
#include "../include/mbedtls/aes.h"
#include "../include/mbedtls/gcm.h"
#include "../include/mbedtls/rsa.h"
#include "../include/mbedtls/entropy.h"
#include "../include/mbedtls/ctr_drbg.h"
#include "../include/mbedtls/bignum.h"
#include "../include/mbedtls/sha1.h"
#include "../include/mbedtls/sha256.h"
#include "../include/WBAC.h"
#include "../include/mbedtls/hmac_drbg.h"
#include "../include/mbedtls/base64.h"
#include "../include/mbedtls/pk.h"
#include "../include/mbedtls/pk_internal.h"


//#include "../include/openssl/sm2.h"

#define READ_MAX  (64)

#define MAX_RSA_BITS (4096)
#define MAX_SM2_KEY (256)
#define MAX_ECC_KEY (512)


#define OPT_ENC (1)
#define OPT_DEC (0)

typedef struct{
    u8 *data;
    u32 dataSize;
}vc_input_info;

typedef struct{
    u8 *data;
    u32 dataSize;
}vc_output_info;


//typedef void (*PADDING_FUNC)(u8 *, u32 *, u8 *);

typedef enum{
  PKCS7_PADDING = 0x00,
  ZERO_PADDING,
  NO_PADDING
}PADDING_MODE;

/******************key************************/

typedef enum{
    KEY_TYPE_AES = 0X0,
    KEY_TYPE_RSA_PUB,
    KEY_TYPE_RSA_PRIV,
    KEY_TYPE_CMAC,
    KEY_TYPE_HMAC,
    KEY_TYPE_SM2_PUB,
    KEY_TYPE_SM2_PRIV,
    KEY_TYPE_SM4,
    KEY_TYPE_ECC_PUB,
    KEY_TYPE_ECC_PRIV,
    KEY_TYPE_ECDH_25519
}vc_key_type;

/*typedef struct {
    u8 keyID;
    vc_key_type key_type;
    u32 keyLen;
    u8 *keyMac;
    void *keyInfo; //for rsa, ecc
}vc_gen_privkey_info;*/

typedef struct {
    u8 keyID;
    vc_key_type key_type;
    u32 keyLen;
    u8 *keyMac;
    void *keyInfo; //for rsa, ecc
}vc_gen_key_info;


typedef struct {
    vc_gen_key_info keyInfo;
    vc_output_info keyData;
    u32 isWhiteBoxEnc;
}vc_storage_key_info;

typedef enum{
    TRANS_CIPHER_AES= 0X0,
    TRANS_CIPHER_RSA,
    //TRANS_CIPHER_P_DBG,          //DEBUG
}key_trans_mod;

typedef struct {
    key_trans_mod trans_mod;
    u8 KeyID;
    void *EncInfo;
}vc_except_key;

typedef struct {
    s32 keyID;
    vc_key_type key_type;
    u32 keyLen;
}vc_cmac_key_info;

typedef struct {
    s32 level;
    void * otherInfo; //////////////////
}vc_authentic_info;

/*********************************************/

/****************aes*************************/
typedef enum{
  AES_ENC_CBC = 0x00,
  AES_ENC_GCM,
  AES_ENC_ECB,
  AES_ENC_OFB,
  AES_ENC_CFB,   //128
  AES_ENC_CTR,
}AES_ENC_MODE;

typedef struct{
    vc_gen_key_info keyInfo;
    AES_ENC_MODE aes_enc_mode;
    PADDING_MODE aes_padding_mode;
    u8* iv;  //16 bytes

	/****for gcm****/
	u8 *addData;
	u32 addLen;
	u8 tagBuf[16];

	u8 tagVerify[16];
	/**************/
}vc_aes_encdec_info;

/*********************************************/

/*****************SM4*************************/
typedef enum{
  SM4_ENC_CBC = 0x00,
  SM4_ENC_ECB,
  SM4_ENC_CFB,
  SM4_ENC_OFB,
  SM4_ENC_CTR
}SM4_ENC_MODE;


typedef struct{
    vc_gen_key_info keyInfo;
    SM4_ENC_MODE sm4_enc_mode;
    PADDING_MODE padding_mode;
    u8* iv;  //16 bytes
}vc_sm4_encdec_info;
/*********************************************/


/****************hash*************************/
typedef enum{
    HASH_MD_NONE = 0,
    HASH_MD_SHA1 = 4,
    HASH_MD_SHA224,
    HASH_MD_SHA256,
    HASH_MD_SHA384,
    HASH_MD_SHA512,
    HASH_SM3 = 0x10
}HASH_ALG;

typedef struct{
    HASH_ALG hash_type;
}vc_hash_info;


/*********************************************/



/****************rsa*************************/
typedef enum{
  RSA_PKCS_V15 = 0x00,
  RSA_PKCS_V21,
  /*!<  MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
        MBEDTLS_RSA_PKCS_v21 for OAEP/PSS         */
}RSA_PADDING_MODE;

typedef struct{
    u8 *N;
    u8 *E;
    u8 *D;
    u8 *P;
    u8 *Q;
    u8 *DP;
    u8 *DQ;
    u8 *QP;
   /* u8 N[1024];
    u8 E[1024];
    u8 D[1024];
    u8 P[1024];
    u8 Q[1024];
    u8 DP[1024];
    u8 DQ[1024];
    u8 QP[1024];*/
}RSA_CONTEXT_STRING;

typedef struct{
    vc_gen_key_info keyInfo;
    RSA_PADDING_MODE rsa_padding_mode; /*!<  Hash identifier of mbedtls_md_type_t as
                                      specified in the mbedtls_md.h header file
                                      for the EME-OAEP and EMSA-PSS
                                      encoding                          */
}vc_rsa_encdec_info;



typedef struct{
    vc_rsa_encdec_info rsa_encdec_info;
    HASH_ALG hash_type;
}vc_rsa_sigver_info;


/*********************************************/

/****************SM2**************************/
typedef struct{
    vc_gen_key_info keyInfo;
}vc_sm2_encdec_info;

typedef struct{
    vc_gen_key_info keyInfo;
    vc_gen_key_info skeyInfo;
    u8 * id;
}vc_sm2_sigver_info;


/*********************************************/


/*****************ECC*************************/
typedef enum
{
    ECP_DP_NONE = 0,
    ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    ECP_DP_CURVE25519,           /*!< Curve25519               */            //cannot use for sign !!
    ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} ecc_group_id;

typedef struct{
    vc_gen_key_info keyInfo;
    HASH_ALG hash_type;
}vc_ecc_encdec_info;

typedef struct{
    vc_gen_key_info keyInfo;
    HASH_ALG hash_type;
}vc_ecc_sigver_info;

typedef struct{
    u32 keyID;
    ecc_group_id ecid;
}vc_ecc_dh_info;
/********************************************/

/*****************MAC************************/

typedef struct{
	vc_gen_key_info keyInfo;
	HASH_ALG hash_type;
}vc_hmac_info;

typedef struct{
    vc_gen_key_info keyInfo;
}vc_cmac_info;

/*********************************************/

/******************CSR/CRT************************/
typedef struct {
    HASH_ALG hashAlg;
    u8 keyID;         // priv key
    u8 key_usage;
    u8 ns_cert_type;
    u8 *subject_name;
    //vc_input_info oid;
   // vc_input_info val;
}vc_csr;

typedef struct {
    u8 crtID;
    u8 *crtMac;
    vc_output_info crtData;
    u32 isWhiteBoxEnc;
}vc_storage_crt_info;

typedef struct {
    s32 crtID;
}vc_except_crt;

/*********************************************/

/***************envelope*********************/
typedef struct {
    vc_gen_key_info keyInfo;  //pub for seal ; prive for open
    vc_aes_encdec_info aesInfo;   //seal need keylen and padding mod;  open need iv buf;  iv may be a random
    vc_input_info cipher;
    vc_input_info aesKeyCipher;   //seal need buf to recv key cipher;  open need key cipher
}vc_envelop_info;
/********************************************/


/*****************ERR NUM***********************/
typedef enum {
    ERR_NO = 0,
    ERR_PARAM,
    ERR_NOT_ENOUGH,
    ERR_SWITH,
    ERR_GET_KEY,
    ERR_AUTH = 5,
    ERR_KEYFILE_BROKEN ,
    ERR_EXPORT_PRIV ,
    ERR_KEY_READ ,
    ERR_MALLOC ,
    ERR_KEYID = 10,
    ERR_KEYLEN ,
    ERR_KEY_NULL,
    ERR_KEY_TYPE ,
    ERR_MAC,
    ERR_ALG_PROCESS = 15,
    ERR_UNDEF,
}ERR_NUM;

/***********************************************/

//void aes_zero_padding(vc_input_info* keyInfo);
void padding(u8 *data , u32 *len, PADDING_MODE m);
void unpading(PADDING_MODE mod, vc_output_info * outdata);
s32 vc_get_aes_key(u32 keyid, vc_output_info* keyInfo);
/*    for origin data
s32 vc_get_rsa_pub_key(u32 keyBits, u8 * filePath, RSA_CONTEXT_STRING* keyInfo);
s32 vc_get_rsa_priv_key(u32 keyBits, u8 * filePath, RSA_CONTEXT_STRING* keyInfo);
*/
s32 vc_get_rsa_pub_key(u32 keyid, mbedtls_pk_context* keyInfo);
s32 vc_get_rsa_priv_key(u32 keyid, mbedtls_pk_context* keyInfo);
s32 vc_get_file_size(u8 * filepath);
s32 vc_check_auth(vc_authentic_info *authInfo);
void vc_white_box_enc(vc_input_info *indata, vc_output_info *outdata);
void vc_white_box_decrypt(vc_input_info *indata, vc_output_info *outdata);
s32 CalcK1K2(vc_input_info* inputkey, u8* k1, u8* k2);
s32 CMAC_AesEnc(vc_input_info* data, vc_input_info* key, u8* iv, vc_output_info* outBuf);
s32 vc_get_hmac_key(u32 keyid, vc_output_info* keyInfo, s32 ishmac);
s32 vc_file_str(u8 * src, const u8 *modStr, u32 modLen, u8 **dst);
s32 checkOutBufferLen(u32 inLen, u32 outLen);
s32 vc_whitebox_with_data(vc_input_info *input, void *output ,int mod);
s32 vc_whitebox_with_file(u8 *infile, void *output, int mod);
s32 vc_hash_len(HASH_ALG type);
s32 vc_kdf(HASH_ALG type ,vc_input_info *zInfo, u32 klen, vc_output_info *kInfo);
void vc_or_data(vc_input_info *in, vc_output_info *out);
void vc_or_data_add(vc_input_info *in, vc_output_info *out);
void vc_sub_data_or(vc_input_info *in, vc_output_info *out);
#endif

