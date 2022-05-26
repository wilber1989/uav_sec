#include "../include/vc_envelope.h"
#include "../include/vc_rsa.h"
#include "../include/vc_aes.h"

s32 do_seal(vc_envelop_info *envIn, vc_input_info *input, vc_envelop_info *output)
{
    s32 res = 0;
    if (envIn == NULL || input == NULL || output == NULL)
    {
        return -ERR_PARAM;
    }

    vc_rsa_encdec_info rsaEncDecInfo;
    rsaEncDecInfo.keyInfo.keyID = envIn->keyInfo.keyID;
    rsaEncDecInfo.rsa_padding_mode = MBEDTLS_RSA_PKCS_V15;

    vc_input_info rsaIn;
    u8 aesKey[64] = {0};
    rsaIn.data = aesKey;
    rsaIn.dataSize = 64;
    vc_aes_encdec_info *aesInfo = &(envIn->aesInfo);
    aesInfo->aes_padding_mode = PKCS7_PADDING;
    res = vc_random_gen(aesInfo->keyInfo.keyLen, (vc_output_info *)&rsaIn);
    if (res != 0)
    {
        VC_LOG_E("do_seal random error %d\n", res);
        goto exit;
    }

    rsaIn.dataSize = aesInfo->keyInfo.keyLen;
    res = do_rsa_encrypt(&rsaEncDecInfo, &rsaIn, (vc_output_info *)&output->aesKeyCipher);
    if (res != 0)
    {
        VC_LOG_E("do_seal do_rsa_encrypt error %d\n", res);
        goto exit;
    }

    res = do_aes_crypt(aesInfo, (vc_output_info *)&rsaIn, input, (vc_output_info *)&(output->cipher), OPT_ENC);
    if (res != 0)
    {
        VC_LOG_E("do_seal do_aes_crypt error %d\n", res);
        goto exit;
    }
exit:
    return res;
}

s32 do_openseal(vc_envelop_info *envIn, vc_output_info *output)
{
    s32 res = 0;

    if (envIn == NULL || output == NULL)
    {
        return -ERR_PARAM;
    }

    vc_rsa_encdec_info rsaEncDecInfo;
    rsaEncDecInfo.rsa_padding_mode = MBEDTLS_RSA_PKCS_V15;
    rsaEncDecInfo.keyInfo.keyID = envIn->keyInfo.keyID;
    rsaEncDecInfo.keyInfo.keyMac = envIn->keyInfo.keyMac;

    vc_input_info rsaIn;
    u8 aesKey[64] = {0};
    rsaIn.data = aesKey;
    rsaIn.dataSize = 64;
    vc_aes_encdec_info *aesInfo = &(envIn->aesInfo);
    aesInfo->aes_padding_mode = PKCS7_PADDING;

    rsaIn.dataSize = sizeof(aesKey);

    res = do_rsa_decrypt(&rsaEncDecInfo, &envIn->aesKeyCipher, (vc_output_info *)&rsaIn);
    if (res != 0)
    {
        VC_LOG_E("do_seal do_rsa_decrypt error %d\n", res);
        goto exit;
    }

    res = do_aes_crypt(aesInfo, (vc_output_info *)&rsaIn, &(envIn->cipher), output, OPT_DEC);
    if (res != 0)
    {
        VC_LOG_E("do_seal do_aes_crypt error %d\n", res);
        goto exit;
    }

exit:
    return res;
}