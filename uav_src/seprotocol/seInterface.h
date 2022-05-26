#ifndef __SE_INTERFACE_H__
#define __SE_INTERFACE_H__
#include "vc_sw_crypt_service.h"
#include "init_so.h"
#include "unit.h"
typedef int32_t s32;
typedef uint8_t u8;

#define CSR_START_HEADER_STR "-----BEGIN CERTIFICATE REQUEST-----\n"
#define CSR_END_HEADER_STR "-----END CERTIFICATE REQUEST-----\n"

#define CERT_FORMAT_STATR_STR "-----BEGIN CERTIFICATE-----\n"
#define CERT_FORMAT_END_STR "-----END CERTIFICATE-----\n"
#define SEPARATOR_FLAG "\n"
#define DEFAULT_STR_LINE_LEN 64

typedef enum{
    FILE_KEY_TYPE_AES = 0X0,
    FILE_KEY_TYPE_RSA_PUB,
    FILE_KEY_TYPE_RSA_PRIV,
    FILE_TYPE_RSA_CRT,
    FILE_TYPE_RSA_PRI,
    FILE_TYPE_CA,    //5
    FILE_TYPE_CRLLIST,
}vc_key_use_type;

#define KEY_IS_NOT_EXIST -1

#define NODE_DATA_LEN 37
typedef struct structNode
{
    u8 data[NODE_DATA_LEN];//数据域// USE_TYPE(1BYTE) |KEY_ID(1BYTE) |KEY_TYPE(1BYTE) |DATA(32BYTE)
    struct structNode *next;//指针域
}KeyAndMacNode;

s32 TST_INIT();
s32 TST_INIT_SO();
s32 genRsaDeviceKeyPair();
s32 TST_AES_GEN_STO_ENC_DEC_MOD();
s32 getpublicKey(vc_output_info *pubkeyDec);
s32 TST_HASH(vc_input_info *indata,vc_output_info *outdata);

s32 initSourceInfo(vc_input_info *input);
s32 genRsaDeviceKeyPair();
s32 getpublicKey(vc_output_info *pubkeyDec);
s32 storageCertAndKeyFile(vc_input_info *inputInfo);
s32 updateKeyAndMacListAndFile(vc_key_use_type keyUse,u8 keyID,s32 keyType,u8 * keyMac);
s32 GEN_CSR(vc_input_info *subjectInfo,vc_output_info * output_csr_data_info);
s32 t_get_deviceid_info(vc_output_info *out);
s32 storageCaCertFile(vc_input_info *ca_cert_info);
s32 storageCrlListCrt(vc_input_info *crlList_info);

s32 isMACKeyExist();
s32 isCaCertFileExist();
s32 isDeviceCertFileExist();
s32 exportFileCert(vc_output_info* outputInfo);
s32 exportCrlListFileCert(vc_output_info* outputInfo);
s32 getKeyIDForKeyUse(vc_key_use_type keyUse);
s32 isRSAKeyExist();
s32 isKeyAndMacFileExist();
s32 isCrlCertFileExist();
s32 readKeyIdAndMacFromFile();
s32 getKeyInfoForKeyUse(vc_key_use_type input_key_use,KeyAndMacNode **keyInfo);
//s32 isKeyAndMacFileExist();
#endif //__SE_INTERFACE_H__


