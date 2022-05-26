#ifndef __VC_SW_CRYPT_SERVICE_H__
#define __VC_SW_CRYPT_SERVICE_H__
#include "vc_sw_crypt.h"

#define MAX_KEY_ID (99)          // 1-99:key file  100-127:temp key
#define MAX_TMP_KEY_ID (127)
#define NUM_TMP_KEY (28)   //127-99
#define MAX_CRT_ID (127)

static const u8 KEY_FILE_PATH[]  = "./";
static const u8 KEY_FILE_NAME[]  = "KEY_";
static const u8 CRT_FILE_PATH[]  = "./";
static const u8 CRT_FILE_NAME[]  = "CRT_";
static const u8 MAC_FILE_PATH[]  = "./";
static const u8 MAC_FILE_NAME[]  = "I_MAC";

typedef s32 (*vc_get_info)(vc_output_info *);

typedef struct {
    u8 keyID;
    u8 *keyMac;
    vc_key_type keyType;
    vc_input_info keyData;
    u32 isWhiteBoxEnc;  // only use to set key file (delete , temp key not need)
}vc_storage_key_st;

typedef vc_except_key vc_except_key_st;

typedef struct {
    vc_key_type keyType;
    u32 keyLen;   //ec algorithm no use it

    void *extInfo; //for rsa, ecc
}vc_gen_key_st;


/****for aes_gcm****/
typedef struct{
    u8 *addData;
    u32 addLen;
    u8 tagBuf[16];
    u8 tagVerify[16];
}vc_aes_gcm_encdec_ext_st;
/**************/

typedef struct{
    u8 keyID;
    AES_ENC_MODE aes_enc_mode;
    PADDING_MODE aes_padding_mode;
    u8* iv;  //16 bytes

    vc_aes_gcm_encdec_ext_st *gcm;
}vc_aes_encdec_st;

typedef struct{
    u8 keyID;
    SM4_ENC_MODE enc_mode;
    PADDING_MODE padding_mode;
    u8* iv;  //16 bytes
}vc_sm4_encdec_st;

typedef struct{
  u8 keyID;
  RSA_PADDING_MODE rsa_padding_mode; /*!<  Hash identifier of mbedtls_md_type_t as
                                      specified in the mbedtls_md.h header file
                                      for the EME-OAEP and EMSA-PSS
                                      encoding                          */
}vc_rsa_encdec_st;

typedef struct{
    vc_rsa_encdec_st encinfo;
    HASH_ALG hash_type;
}vc_rsa_sigver_st;

typedef struct{
    u8 keyID;
}vc_sm2_encdec_st;

typedef struct {
    u8 keyID;
    u8 skeyID;
    u8 *id;
}vc_sm2_sigver_st;

typedef struct{
    u8 keyID;
    HASH_ALG hash_type;
}vc_ecc_encdec_st;

typedef vc_ecc_encdec_st vc_ecc_sigver_st;

typedef vc_ecc_encdec_st vc_hmac_st;
typedef vc_sm2_encdec_st vc_cmac_st;

typedef vc_hash_info vc_hash_st;

typedef vc_csr vc_csr_st;

typedef struct {
    u8 keyID;

    u32 aesKeyLen;
    AES_ENC_MODE aes_enc_mode;
    u8* iv;  //16 bytes
}vc_envelope_in_st;

typedef struct {
    u8 keyID;

    AES_ENC_MODE aes_enc_mode;
    u8* iv;  //16 bytes

    vc_output_info cipher;
    vc_output_info aeskeycipher;
}vc_envelope_out_st;

typedef vc_storage_crt_info vc_storage_crt_st;

typedef vc_except_crt vc_except_crt_st;

__attribute__ ((visibility("default")))
s32 vc_init(vc_get_info f, vc_output_info* out);
__attribute__ ((visibility("default")))
s32 vc_delete_initso(u8 *filepath);
__attribute__ ((visibility("default")))
s32 vc_storage_key(vc_storage_key_st *storageKeyInfo);
__attribute__ ((visibility("default")))
s32 vc_storage_tmp_key(vc_storage_key_st * storageInfo);
__attribute__ ((visibility("default")))
s32 vc_delete_key(vc_storage_key_st *storageKeyInfo);
__attribute__ ((visibility("default")))
s32 vc_delete_tmp_key(vc_storage_key_st * storageInfo);
__attribute__ ((visibility("default")))
s32 vc_export_key(vc_except_key_st *exceptKeyInfo,vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_export_tmp_key(vc_except_key_st *exceptKeyInfo,vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_aes_encrypt(vc_aes_encdec_st* aesEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_aes_decrypt(vc_aes_encdec_st* aesEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm4_encrypt(vc_sm4_encdec_st* sm4EncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm4_decrypt(vc_sm4_encdec_st* sm4EncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_encrypt(vc_rsa_encdec_st* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_decrypt(vc_rsa_encdec_st* rsaEncDecInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_sign(vc_rsa_sigver_st * rsaSigVerInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_sign_file(vc_rsa_sigver_st * rsaSigVerInfo, u8* filePath, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_verify(vc_rsa_sigver_st * rsaSigVerInfo, vc_input_info* inputInfo, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_rsa_verify_file(vc_rsa_sigver_st * rsaSigVerInfo, u8* filePath, vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm2_enc(vc_sm2_encdec_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm2_dec(vc_sm2_encdec_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm2_sign(vc_sm2_sigver_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
__attribute__ ((visibility("default")))
s32 vc_sm2_verify(vc_sm2_sigver_st *encInfo,    vc_input_info *inputInfo, vc_output_info *outputInfo);
__attribute__ ((visibility("default")))
s32 vc_ecc_enc(vc_ecc_encdec_st * encInfo, vc_input_info * inputInfo, vc_output_info * outputInfo);
__attribute__ ((visibility("default")))
s32 vc_ecc_dec(vc_ecc_encdec_st * encInfo, vc_input_info * inputInfo, vc_output_info * outputInfo);
__attribute__ ((visibility("default")))
s32 vc_ecdsa_sign(vc_ecc_sigver_st *sigInfo, vc_input_info* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2);
__attribute__ ((visibility("default")))
s32 vc_ecdsa_verify(vc_ecc_sigver_st *sigInfo, vc_input_info* inInfo, vc_output_info* outputInfo1, vc_output_info* outputInfo2);
__attribute__ ((visibility("default")))
s32 vc_ecdsa_sign_file(vc_ecc_sigver_st *sigInfo, u8* filePath, vc_output_info* outputInfo1, vc_output_info* outputInfo2);
__attribute__ ((visibility("default")))
s32 vc_ecdsa_verify_file(vc_ecc_sigver_st *sigInfo, u8* filePath, vc_output_info* outputInfo1, vc_output_info* outputInfo2);
__attribute__ ((visibility("default")))
s32 vc_ecdh_shared_key(vc_input_info *privInfo, vc_input_info *pubInfo , vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_random_gen(u32 ran_len,vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_hmac_genkey(vc_gen_key_st *genKeyInfo,  vc_output_info *outdata);
__attribute__ ((visibility("default")))
s32 vc_cmac_genkey(vc_gen_key_st *genKeyInfo,  vc_output_info *outdata);
__attribute__ ((visibility("default")))
s32 vc_CalcHmac(vc_hmac_st *hmac_info, vc_input_info *input, vc_output_info *hmac);
__attribute__ ((visibility("default")))
s32 vc_asym_genkey(vc_gen_key_st *genKeyInfo,  vc_output_info *pubKey, vc_output_info *privKey);
__attribute__ ((visibility("default")))
s32 vc_sym_genkey(vc_gen_key_st *genKeyInfo,  vc_output_info *outdata);
__attribute__ ((visibility("default")))
s32 vc_CalcCmac(vc_input_info     *input,  vc_cmac_st *keyInfo, vc_output_info *cmac);
__attribute__ ((visibility("default")))
s32 vc_VerifyCmac(vc_input_info     *input,  vc_cmac_st *keyInfo, vc_output_info *cmac);
__attribute__ ((visibility("default")))
s32 vc_Base64Encode(vc_input_info *input, vc_output_info *output);
__attribute__ ((visibility("default")))
s32 vc_Base64Decode(vc_input_info *input, vc_output_info *output);
__attribute__ ((visibility("default")))
s32 vc_hash(vc_hash_st *hashInfo, vc_input_info*  inputInfo,  vc_output_info* outputInfo);
__attribute__ ((visibility("default")))
s32 vc_hash_file(vc_hash_st *hashInfo, u8* inputFile,  vc_output_info* outputInfo);
/*
s32 vc_whitebox_enc_data(vc_input_info *input, void *outfile);
s32 vc_whitebox_dec_data(vc_input_info *input, void *output);
s32 vc_whitebox_enc_file(u8 *infile, void *outfile);
s32 vc_whitebox_dec_file(u8 *infile, void *output);
*/
__attribute__ ((visibility("default")))
s32 vc_parse_crt_pubkey(u8 crtID, vc_output_info *outInfo);
__attribute__ ((visibility("default")))
s32 vc_verify_crt(vc_input_info *crtInfo, u8 caID, u8 crlID, u8 *cn);
__attribute__ ((visibility("default")))
s32 vc_gen_csr(vc_csr_st * csrInfo, vc_output_info * output);
__attribute__ ((visibility("default")))
s32 vc_enveloped_seal(vc_envelope_in_st *envIn, vc_input_info *input, vc_envelope_out_st *output);
__attribute__ ((visibility("default")))
s32 vc_enveloped_openseal(vc_envelope_out_st *envIn, vc_output_info *output);
__attribute__ ((visibility("default")))
s32 vc_storage_crt(vc_storage_crt_st * storageCrtInfo);
__attribute__ ((visibility("default")))
s32 vc_delete_crt(vc_storage_crt_st * storageCrtInfo);
__attribute__ ((visibility("default")))
s32 vc_export_crt(vc_except_crt_st *crtInfo,vc_output_info* outputInfo);
#endif
