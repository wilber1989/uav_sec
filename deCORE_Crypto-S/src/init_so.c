#include "../include/init_so.h"
#include "../include/vc_key.h"

s32 init_so(vc_get_info f, vc_output_info* out)
{
    s32 res = 0;

    if (f == NULL || out == NULL)
        res = -ERR_PARAM;

    vc_output_info macout;
    u8 buf[64] = {0};
    macout.data = buf;
    macout.dataSize = 64;

    res = f(out);
    if (res != 0)
        return res;

    HASH_ALG htype;
    htype = HASH_MD_SHA256;
    res = vc_kdf(htype, (vc_input_info *)out, 64*8, &macout);
    if (res != 0)
        return res;

    u8 tmpStr[128] = {0};
    FILE *fp;
    sprintf(tmpStr, "%s%s", MAC_FILE_PATH, MAC_FILE_NAME);
    fp = fopen(tmpStr ,"wb");
    if (fp == NULL)
        return -ERR_PARAM;

    vc_output_info macbuf;
    macbuf.data = tmpStr;
    macbuf.dataSize = sizeof(tmpStr);

    vc_white_box_enc((vc_input_info*)&macout, &macbuf);

    res = fwrite(macbuf.data, macbuf.dataSize, 1, fp);
    if (res <= 0)
        VC_LOG_E("init_so write file error\n");
    else
        res = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    return res;
}