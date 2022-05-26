#include "../include/vc_hash.h"

void hash_file_sha1(FILE *fin, vc_output_info* outputInfo)
{
    vc_input_info inputInfo;
    u8 readData[64] = {0};
    inputInfo.data = readData;
    inputInfo.dataSize = 64;
    u32 readlen = 0;

    mbedtls_sha1_context ctx;
    mbedtls_sha1_init( &ctx );
    mbedtls_sha1_starts( &ctx );
    u8 out[20] = {0};

    while(1)
    {
        readlen = fread(inputInfo.data, 1, READ_MAX,fin);
        if (readlen == 0)
            break;


        inputInfo.dataSize = readlen;

        mbedtls_sha1_update( &ctx, inputInfo.data, inputInfo.dataSize);
    }

    mbedtls_sha1_finish(&ctx, out);
    memcpy(outputInfo->data, out, 20);
    outputInfo->dataSize = 20;
    mbedtls_sha1_free( &ctx );
}

void hash_file_sha224(FILE *fin, vc_output_info* outputInfo, int is224)
{
    vc_input_info inputInfo;
    u8 readData[64] = {0};
    inputInfo.data = readData;
    inputInfo.dataSize = 64;
    u32 readlen = 0;

    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, is224);
    u8 out[32] = {0};

    while(1)
    {
        readlen = fread(inputInfo.data, 1, READ_MAX,fin);
        if (readlen == 0)
            break;


        inputInfo.dataSize = readlen;

        mbedtls_sha256_update( &ctx, inputInfo.data, inputInfo.dataSize);
    }

    mbedtls_sha256_finish(&ctx, out);
    memcpy(outputInfo->data, out, 32);
    outputInfo->dataSize = 32;
    mbedtls_sha256_free( &ctx );
}

void hash_file_sha384(FILE *fin, vc_output_info* outputInfo, int is384)
{
    vc_input_info inputInfo;
    u8 readData[64] = {0};
    inputInfo.data = readData;
    inputInfo.dataSize = 64;
    u32 readlen = 0;

    mbedtls_sha512_context ctx;

    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, is384);
    u8 out[64] = {0};

    while(1)
    {
        readlen = fread(inputInfo.data, 1, READ_MAX,fin);
        if (readlen == 0)
            break;


        inputInfo.dataSize = readlen;

        mbedtls_sha512_update( &ctx, inputInfo.data, inputInfo.dataSize);
    }

    mbedtls_sha512_finish(&ctx, out);
    memcpy(outputInfo->data, out, 64);
    outputInfo->dataSize = 64;
    mbedtls_sha512_free( &ctx );
}

#ifdef SMENABLE
void hash_file_sm3(FILE *fin, vc_output_info* outputInfo)
{
    vc_input_info inputInfo;
    u8 readData[64] = {0};
    inputInfo.data = readData;
    inputInfo.dataSize = 64;
    u32 readlen = 0;

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    u8 out[32] = {0};

    while(1)
    {
        readlen = fread(inputInfo.data, 1, READ_MAX,fin);
        if (readlen == 0)
            break;


        inputInfo.dataSize = readlen;

        sm3_update(&ctx, inputInfo.data, inputInfo.dataSize);
    }

    sm3_final(&ctx, out);
    memcpy(outputInfo->data, out, 32);
    outputInfo->dataSize = 32;
    memset(&ctx, 0, sizeof(sm3_ctx_t));
}
#endif

