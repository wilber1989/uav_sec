#include "unit.h"
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
    V2X_VECEN_DEBUG_PRINTF("%s == %s\n",tag,binstr);
}

//return len
int32_t HexStrSwitch2ByteArray(char s[],char bits[]) {
    int32_t i,n = 0;
    for(i = 0; s[i]; i += 2) {
        if(s[i] >= 'A' && s[i] <= 'F')
        {
            bits[n] = s[i] - 'A' + 10;
        }
        else if(s[i] >= 'a' && s[i] <= 'f')
        {
            bits[n] = s[i] - 'a' + 10;
        }
        else
        {
            bits[n] = s[i] - '0';
        }
        if(s[i + 1] >= 'A' && s[i + 1] <= 'F')
        {
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
        }
        else if(s[i + 1] >= 'a' && s[i + 1] <= 'f')
        {
           bits[n] = (bits[n] << 4) | (s[i + 1] - 'a' + 10);
        }
        else
        {
            bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
        }
        ++n;
    }
    return n;
}
