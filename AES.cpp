#include <bits/stdc++.h>
#ifndef __SymmetricKeyCipher__AES__
#endif // __SymmetricKeyCipher__AES__#define __SymmetricKeyCipher__AES__
using namespace std;
typedef unsigned char byte;
typedef unsigned int  word;
const int Nr = 10;  // AES-128需要 10 轮加密
const int Nk = 4;   // Nk 表示输入密钥的 word 个数
//S盒
static byte SBox[16][16]= {{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};
//逆S盒
static byte SBoxInv[16][16]= {{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0X6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};
//列混淆矩阵
static byte MixMatr[4][4]= {{0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};
//逆列混淆矩阵
static byte MixMatrInv[4][4]= {{0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};
//密钥扩展中的轮常量
static word Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
                       };

byte key[16] = {0x2b, 0x7e, 0x15, 0x16,
                0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c
               };
byte Iv[16] = {0x20, 0x70, 0x01, 0x06,
               0x10, 0x50, 0x02, 0x06,
               0x30, 0x60, 0x05, 0x08,
               0x40, 0x80, 0x04, 0x03
              };
byte Ivde[16] = {0x20, 0x70, 0x01, 0x06,
                 0x10, 0x50, 0x02, 0x06,
                 0x30, 0x60, 0x05, 0x08,
                 0x40, 0x80, 0x04, 0x03
                };
byte mmp[99999][4][4];
string file_path,file_save;

//十六进制字符串转换为字节流
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return;
}

/****************************加密的变换函数****************************/
//字节替代
void Subsitute_Byte(byte state[][4])
{
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j] = SBox[state[i][j]/16][state[i][j]%16];
}

//左移
void LeftMove(byte *word, int offset)
{
    byte temp[4];
    for(int i=0; i < 4; i++)
        temp[(i + 4 - offset) % 4] = word[i];
    for(int i = 0; i < 4; i++)
        word[i] = temp[i];
}
//行移位
void ShiftRows(byte state[4][4])
{
    //第一行移位0位；第二行移位1位；第三行移位2位；第四行移位3位
    for(int i=0; i<4; i++)
        LeftMove(state[i],i);
}

//有限域上的乘法 GF(2^8)
byte GFMul(byte MatrixValue, byte StateValue)
{
    byte temp = 0;
    byte hbs;
    for(int i=0; i<8; i++)
    {
        if((StateValue & byte(1))!=0)
        {
            temp ^= MatrixValue;
        }
        hbs = (byte) (MatrixValue & byte(0x80));
        MatrixValue <<= 1;
        if (hbs != 0)
        {
            MatrixValue ^= 0x1b;
        }
        StateValue >>= 1;
    }
    return temp;
}
//列混淆
void MixColumns(byte state[4][4])
{
    byte temp[4][4];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            temp[i][j] = state[i][j];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j]=GFMul(MixMatr[i][0], temp[0][j]) ^ GFMul(MixMatr[i][1], temp[1][j]) ^
                        GFMul(MixMatr[i][2], temp[2][j]) ^ GFMul(MixMatr[i][3], temp[3][j]);
}

void AddRoundKey(byte state[][4], word key[4])
{
    byte bytekey[Nk][Nk];
    for(int i=0; i<Nk; i++)
    {
        bytekey[i][0] = (key[i] >> 24) & 0x000000ff;
        bytekey[i][1] = (key[i] >> 16) & 0x000000ff;
        bytekey[i][2] = (key[i] >> 8) & 0x000000ff;
        bytekey[i][3] = key[i] & 0x000000ff;
    }
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j] = state[i][j] ^ bytekey[i][j];
}

/****************************解密的变换函数****************************/
//逆字节替代
void Subsitute_Byte_Inv(byte state[][4])
{
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j] = SBoxInv[state[i][j]/16][state[i][j]%16];
}

//右移
void RightMove(byte *word, int offset)
{
    byte temp[4];
    for(int i=0; i < 4; i++)
        temp[(i + 4 + offset) % 4] = word[i];
    for(int i = 0; i < 4; i++)
        word[i] = temp[i];
}
//逆行移位
void ShiftRowsInv(byte state[4][4])
{
    for(int i=0; i<4; i++)
        RightMove(state[i],i);
}

//逆列混淆
void MixColumnsInv(byte state[4][4])
{
    byte temp[4][4];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            temp[i][j] = state[i][j];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j]=GFMul(MixMatrInv[i][0], temp[0][j]) ^ GFMul(MixMatrInv[i][1], temp[1][j]) ^
                        GFMul(MixMatrInv[i][2], temp[2][j]) ^ GFMul(MixMatrInv[i][3], temp[3][j]);
}

/****************************密钥扩展****************************/
// 将k1k2k3k4转换为一个 w0.
word Word(byte &k1, byte &k2, byte &k3, byte &k4)
{
    word result;
    word temp;
    word temp1 = k1 << 24;
    word temp2 = k2 << 16;
    word temp3 = k3 << 8;
    word temp4 = k4;
    result = temp1 | temp2 | temp3 | temp4;
    return result;
}

//循环左移一位
word RotWord(word &rw)
{
    word high = rw << 8;
    word low = rw >> 24;
    return high | low;
}

//对输入word中的每一个字节进行S盒变换
word SubWord(word wordvalue)
{
    byte temp[4];
    word result ;
    temp[0] = (wordvalue >> 24) & 0x000000ff; //1E
    temp[1] = (wordvalue >> 16) & 0x000000ff; //4D
    temp[2] = (wordvalue >> 8) & 0x000000ff;  //7C
    temp[3] = wordvalue & 0x000000ff; //8B
    temp[0] = SBox[temp[0]/16][temp[0]%16]; // 1  14
    temp[1] = SBox[temp[1]/16][temp[1]%16];// 4  13
    temp[2] = SBox[temp[2]/16][temp[2]%16];// 7  12
    temp[3] = SBox[temp[3]/16][temp[3]%16]; //8  11
    result =Word(temp[0], temp[1], temp[2], temp[3]);
    return result;
}

// 密钥扩展函数,对128位密钥进行扩展得到 w[4*(Nr+1)]
void KeyExpansion(byte key[4*Nk],word w[4*(Nr+1)])
{
    word temp;
    int i = 0;
    byte bytevalue[4] = {0};
    for(int i=0; i<Nk; i++)
    {
        w[i] = Word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
    }
    for(int i=Nk; i<4*(Nr+1); i++)
    {
        temp = w[i-1];
        if(i%Nk == 0)
        {
            RotWord(temp);
            w[i] =w[i-Nk] ^ SubWord(temp) ^ Rcon[i/Nk-1];
        }
        else
            w[i] = w[i-4] ^ temp;
    }

}

/****************************加密过程****************************/
void AES_Encryption(byte state[][4], word w[4*(Nr+1)])
{
    word key[4];
    for(int i=0; i<4; i++)
        key[i] = w[i];
    AddRoundKey(state, key);
    for(int round=1; round<=9; round++)
    {
        //字节替代
        Subsitute_Byte(state);
        //行移位
        ShiftRows(state);
        //列混淆
        MixColumns(state);
        //轮密钥加
        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];
        AddRoundKey(state, key);
    }
    //第十轮
    Subsitute_Byte(state);
    ShiftRows(state);
    for(int i=0; i<4; ++i)
        key[i] = w[4*Nr+i];
    AddRoundKey(state, key);
}

//与初始向量异或
void XorIv(byte state[][4], byte Iv[16])
{
    int time = 0;
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
        {
            state[i][j] = state[i][j] ^ Iv[time];
            time ++;
        }

}
void AES_Encryption_CBC(byte state[][4], word w[4*(Nr+1)], byte Iv[16])
{
    word key[4];
    XorIv(state,Iv);
    for(int i=0; i<4; i++)
        key[i] = w[i];
    AddRoundKey(state, key);
    for(int round=1; round<=9; round++)
    {
        //字节替代
        Subsitute_Byte(state);
        //行移位
        ShiftRows(state);
        //列混淆
        MixColumns(state);
        //轮密钥加
        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];
        AddRoundKey(state, key);
    }
    //第十轮
    Subsitute_Byte(state);
    ShiftRows(state);
    for(int i=0; i<4; ++i)
        key[i] = w[4*Nr+i];
    AddRoundKey(state, key);
    //加密后的密文作为下一轮的IV

    int temptime = 0;
    byte temp[4*Nk];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
        {
            temp[temptime] = state[i][j];
            temptime++;
        }
    memcpy(Iv,temp,16);
}

/****************************解密过程****************************/
void AES_Decryption(byte state[][4], word w[4*(Nr+1)])
{
    word key[4];
    for(int i=0; i<4; i++)
        key[i] = w[4*Nr+i];
    AddRoundKey(state, key);
    for(int round=Nr-1; round>0; round--)
    {
        ShiftRowsInv(state);
        Subsitute_Byte_Inv(state);
        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];
        AddRoundKey(state, key);
        MixColumnsInv(state);
    }
    //第十轮
    ShiftRowsInv(state);
    Subsitute_Byte_Inv(state);
    for(int i=0; i<4; ++i)
        key[i] = w[i];
    AddRoundKey(state, key);
}

void AES_Decryption_CBC(byte state[][4], word w[4*(Nr+1)], byte Iv[16])
{
    //先保存密文，用于作为下一分组的密文的链接向量
    int temptime = 0;
    byte temp[4*Nk];
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
        {
            temp[temptime] = state[i][j];
            temptime++;
        }

    word key[4];
    for(int i=0; i<4; i++)
        key[i] = w[4*Nr+i];
    AddRoundKey(state, key);
    for(int round=Nr-1; round>0; round--)
    {
        ShiftRowsInv(state);
        Subsitute_Byte_Inv(state);
        for(int i=0; i<4; ++i)
            key[i] = w[4*round+i];
        AddRoundKey(state, key);
        MixColumnsInv(state);
    }
    //第十轮
    ShiftRowsInv(state);
    Subsitute_Byte_Inv(state);
    for(int i=0; i<4; ++i)
        key[i] = w[i];
    AddRoundKey(state, key);
    XorIv(state,Iv);
    memcpy(Iv,temp,16);
}
void load1(int &size,int &geshu)
{
    // 读文件
    char * buffer;
    ifstream file (file_path,ios::in|ios::binary|ios::ate);
    size = file.tellg(); //原文件大小
    geshu=size%16==0?size/16:size/16+1;
    file.seekg (0, ios::beg);
    buffer = new char [geshu*16];
    file.read (buffer, size);
    file.close();

    int jishuqi=0;
    for(int i=0; i<geshu; ++i)
        for(int u=0; u<4; ++u)
            for(int o=0; o<4; ++o)
                if(jishuqi<size)
                    mmp[i][u][o]=(int)buffer[jishuqi++];
                else
                    mmp[i][u][o]=65;
    // 配置信息
    string Configuration_file_path=file_path+"c";
    ofstream file1 (Configuration_file_path,ios::out);
    file1<<size<<endl<<geshu<<endl;
    file1.close();
}

void load2(int &size,int &geshu)
{
    // 配置信息
    string Configuration_file_path=file_path+"c";
    ifstream file2(Configuration_file_path,ios::in);
    file2>>size>>geshu;
    file2.close();

    remove(Configuration_file_path.c_str());

    // 读文件
    char * buffer;
    ifstream file (file_path,ios::in|ios::binary|ios::ate);
    file.seekg (0, ios::beg);
    buffer = new char [geshu*16];
    file.read (buffer, geshu*16);
    file.close();

    int jishuqi=0;
    for(int i=0; i<geshu; ++i)
        for(int u=0; u<4; ++u)
            for(int o=0; o<4; ++o)
                mmp[i][u][o]=(int)buffer[jishuqi++];
}

void save1(int geshu)
{
    // 写文件
    char buffer[geshu*16];
    int jishuqi=0;
    for(int i=0; i<geshu; ++i)
        for(int u=0; u<4; ++u)
            for(int o=0; o<4; ++o)
                buffer[jishuqi++]=mmp[i][u][o];
    ofstream file (file_path,ios::binary);
    file.write(buffer,geshu*16);
    file.close();
}

void save2(int size,int geshu)
{
    // 写文件
    char buffer[size];
    int jishuqi=0;
    for(int i=0; i<geshu; ++i)
        for(int u=0; u<4; ++u)
            for(int o=0; o<4; ++o)
                if(jishuqi<size)
                    buffer[jishuqi++]=mmp[i][u][o];
    ofstream file (file_path,ios::binary);
    file.write(buffer,size);
    file.close();
}

int main()
{
    cout<<"警告！若对同一文件多次加密，将导致无法正确解密。"<<endl<<endl<<endl;
    word w[4*(Nr+1)];
    KeyExpansion(key, w);
    while(1)
    {
        cout<<"请输入加解密文件路径(退出请输入ESC)：";
        cin>>file_path;
        if(file_path=="ESC")
            return 0;
        cout << endl;
        cout << "1. ECB模式的AES加密" << endl;
        cout << "2. ECB模式的AES解密" << endl;
        cout << "3. CBC模式的AES加密" << endl;
        cout << "4. CBC模式的AES解密" << endl;
        cout << "0. 退出" << endl<<endl;
        cout << "请输入你的选择：";
        int n;
        cin >> n;
        cout<<endl;
        switch(n)
        {
        case 1:
        {
            int size,geshu;
            load1(size,geshu);
            for(int i=0; i<geshu; ++i)
                AES_Encryption(mmp[i],w);
            save1(geshu);
            cout <<"加密完成！"<<endl<<endl;
            break;
        }
        case 2:
        {
            int size,geshu;
            load2(size,geshu);
            for(int i=0; i<geshu; ++i)
                AES_Decryption(mmp[i],w);
            save2(size,geshu);
            cout <<"解密完成！"<<endl<<endl;
            break;
        }
        case 3:
        {
            int size,geshu;
            load1(size,geshu);
            for(int i=0; i<geshu; ++i)
                AES_Encryption_CBC(mmp[i],w,Iv);
            save1(geshu);
            cout <<"加密完成！"<<endl<<endl;
            break;
        }
        case 4:
        {
            int size,geshu;
            load2(size,geshu);
            for(int i=0; i<geshu; ++i)
                AES_Decryption_CBC(mmp[i],w,Ivde);
            save2(size,geshu);
            cout <<"解密完成！"<<endl<<endl;
            break;
        }
        case 0:
            return 0;
        }
    }
}

/*
F:\\云计算\\a.txt
*/
