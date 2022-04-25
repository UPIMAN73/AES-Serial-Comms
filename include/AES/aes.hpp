/**
 * @file aes.hpp
 * @author Joshua Calzadillas 
 * @brief 
 * @version 0.1
 * @date 2022-04-23
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef AES_HPP_
#define AES_HPP_

#pragma once

#include <stdio.h>
#include <cstring>
#include <stdexcept>
#include "alt.hpp"

#ifndef uint8_t
#define uint8_t         unsigned char
#define uint32_t        unsigned int
#endif

// AES Standard Definitions
#define BLOCK_SIZE              16  // # of bytes each block is size
#define BLOCK_ARRAY_SIZE        16  // block array size 

// AES 128 bit definitions
#define AES_128_ROUNDS          10  // Number of rounds
#define AES_128_KEY_SIZE        16  // Minimum key size 
#define AES_128_BKey_Size        4  // Block Key size

/**
 * @brief 
 * AES Encryption Types Supported:
 * - AES 128 bit Encryption
 * 
 */


// Private Functions
void subBytes(uint8_t **mat);
void shiftRow(uint8_t **mat, int i, int n);
void shiftRows(uint8_t **mat);
uint8_t xtime(uint8_t b);
void mixColumns(uint8_t **mat);
void addRoundKey(uint8_t **mat, uint8_t *key);
void subWord(uint8_t *a);
void rotWord(uint8_t *a);
void xorWords(uint8_t *a, uint8_t *b, uint8_t *c, uint32_t len);
void rCon(uint8_t *a, int n);
void invSubBytes(uint8_t **mat);
void invMixColumns(uint8_t **mat);
void invShiftRows(uint8_t **mat);
void checkLength(unsigned int len);
void keyExpansion(uint8_t * key, uint8_t * w);

void encryptBlock(uint8_t * in, uint8_t * out, uint8_t *  rkeys);
void decryptBlock(uint8_t * in, uint8_t * out, uint8_t *  rkeys);


uint32_t blockBytesLen = 4 * AES_128_BKey_Size;

/**
 * @brief 
 * 
 * @param mat 
 */
void subBytes(uint8_t ** mat)
{
    int i, j;
    uint8_t t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
            t = mat[i][j];
            mat[i][j] = sbox[t / 16][t % 16];
        }
    }
}

/**
 * @brief 
 * 
 * @param a 
 */
void subWord(uint8_t * a)
{
    int i;
    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}


/**
 * @brief 
 * 
 * @param mat 
 * @param i 
 * @param n 
 */
void shiftRow(uint8_t ** mat, int i, int n)
{
    uint8_t *tmp = new uint8_t[AES_128_BKey_Size];
    for (int j = 0; j < AES_128_BKey_Size; j++) {
        tmp[j] = mat[i][(j + n) % AES_128_BKey_Size];
    }
    memcpy(mat[i], tmp, AES_128_BKey_Size * sizeof(uint8_t));

    delete[] tmp;
}

/**
 * @brief 
 * 
 * @param mat 
 */
void shiftRows(uint8_t ** mat)
{
    shiftRow(mat, 1, 1);
    shiftRow(mat, 2, 2);
    shiftRow(mat, 3, 3);
}

/**
 * @brief 
 * 
 * @param b 
 * @return uint8_t 
 */
uint8_t xtime(uint8_t b)
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

/**
 * @brief 
 * 
 * @param mat 
 */
void mixColumns(uint8_t ** mat)
{
    uint8_t temp_mat[4][4];
    for (uint32_t i = 0; i < 4; ++i) {
        memset(temp_mat[i], 0, 4);
    }

    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t k = 0; k < 4; ++k) {
        for (uint32_t j = 0; j < 4; ++j) {
            if (CMDS[i][k] == 1)
            temp_mat[i][j] ^= mat[k][j];
            else
            temp_mat[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][mat[k][j]];
        }
        }
    }

    for (uint32_t i = 0; i < 4; ++i) {
        memcpy(mat[i], temp_mat[i], 4);
    }
}

/**
 * @brief 
 * 
 * @param mat 
 * @param key 
 */
void addRoundKey(uint8_t ** mat, uint8_t * key)
{
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < AES_128_BKey_Size; j++) {
      mat[i][j] = mat[i][j] ^ key[i + 4 * j];
    }
  }
}

/**
 * @brief 
 * 
 * @param a 
 */
void rotWord(uint8_t * a)
{
    uint8_t c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

/**
 * @brief 
 * 
 * @param a 
 * @param b 
 * @param c 
 */
void xorWords(uint8_t * a, uint8_t * b, uint8_t * c)
{
    int i;
    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

/**
 * @brief 
 * 
 * @param a 
 * @param n 
 */
void rCon(uint8_t * a, int n)
{
    int i;
    uint8_t c = 1;
    for (i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

/**
 * @brief 
 * 
 * @param mat 
 */
void invSubBytes(uint8_t ** mat)
{
    int i, j;
    uint8_t t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
        t = mat[i][j];
        mat[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

/**
 * @brief 
 * 
 * @param mat 
 */
void invMixColumns(uint8_t ** mat)
{
    uint8_t temp_mat[4][4];

    for (uint32_t i = 0; i < 4; ++i) {
        memset(temp_mat[i], 0, 4);
    }

    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t k = 0; k < 4; ++k) {
        for (uint32_t j = 0; j < 4; ++j) {
            temp_mat[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][mat[k][j]];
        }
        }
    }

    for (uint32_t i = 0; i < 4; ++i) {
        memcpy(mat[i], temp_mat[i], 4);
    }
}

/**
 * @brief 
 * 
 * @param mat 
 */
void invShiftRows(uint8_t ** mat)
{
    shiftRow(mat, 1, AES_128_BKey_Size - 1);
    shiftRow(mat, 2, AES_128_BKey_Size - 2);
    shiftRow(mat, 3, AES_128_BKey_Size - 3);
}

/**
 * @brief 
 * 
 * @param len 
 */
void checkLength(uint32_t len)
{
//     if (len % blockBytesLen != 0) {
//     throw std::length_error("Plaintext length must be divisible by " +
//                             std::to_string(blockBytesLen));
//   }
}

/**
 * @brief 
 * 
 * @param key 
 * @param w 
 */
void keyExpansion(uint8_t * key, uint8_t * w)
{
    unsigned char *temp = new unsigned char[4];
    unsigned char *rcon = new unsigned char[4];

    int i = 0;
    while (i < 4 * AES_128_BKey_Size) {
        w[i] = key[i];
        i++;
    }

    i = 4 * AES_128_BKey_Size;
    while (i < 4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % AES_128_BKey_Size == 0) {
        rotWord(temp);
        subWord(temp);
        rCon(rcon, i / (AES_128_BKey_Size * 4));
        xorWords(temp, rcon, temp);
        } else if (AES_128_BKey_Size > 6 && i / 4 % AES_128_BKey_Size == 4) {
            subWord(temp);
        }

        w[i + 0] = w[i - 4 * AES_128_BKey_Size] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * AES_128_BKey_Size] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * AES_128_BKey_Size] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * AES_128_BKey_Size] ^ temp[3];
        i += 4;
    }

    delete[] rcon;
    delete[] temp;
}

/**
 * @brief 
 * 
 * @param a 
 * @param b 
 * @param c 
 */
void xorBlocks(uint8_t * a, uint8_t * b, uint8_t * c, uint32_t len)
{
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}


/**
 * @brief 
 * 
 * @param in 
 * @param out 
 * @param rkeys 
 */
void encryptBlock(uint8_t * in, uint8_t * out, uint8_t *  rkeys)
{
    uint8_t **mat = new uint8_t *[4];
    mat[0] = new uint8_t[4 * AES_128_BKey_Size];
    int i, j, round;
    for (i = 0; i < 4; i++) {
        mat[i] = mat[0] + AES_128_BKey_Size * i;
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
        mat[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(mat, rkeys);

    for (round = 1; round <= AES_128_ROUNDS - 1; round++) {
        subBytes(mat);
        shiftRows(mat);
        mixColumns(mat);
        addRoundKey(mat, rkeys + round * 4 * AES_128_BKey_Size);
    }

    subBytes(mat);
    shiftRows(mat);
    addRoundKey(mat, rkeys + AES_128_ROUNDS * 4 * AES_128_BKey_Size);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
        out[i + 4 * j] = mat[i][j];
        }
    }

    delete[] mat[0];
    delete[] mat;
}


/**
 * @brief 
 * 
 * @param in 
 * @param out 
 * @param key 
 */
void decryptBlock(uint8_t * in, uint8_t * out, uint8_t * rkeys)
{
    uint8_t **mat = new uint8_t *[4];
    mat[0] = new uint8_t[4 * AES_128_BKey_Size];
    int i, j, round;
    for (i = 0; i < 4; i++) {
        mat[i] = mat[0] + AES_128_BKey_Size * i;
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
        mat[i][j] = in[i + 4 * j];
        }
    }

    addRoundKey(mat, rkeys + AES_128_ROUNDS * 4 * AES_128_BKey_Size);

    for (round = AES_128_ROUNDS - 1; round >= 1; round--) {
        invSubBytes(mat);
        invShiftRows(mat);
        addRoundKey(mat, rkeys + round * 4 * AES_128_BKey_Size);
        invMixColumns(mat);
    }

    invSubBytes(mat);
    invShiftRows(mat);
    addRoundKey(mat, rkeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < AES_128_BKey_Size; j++) {
        out[i + 4 * j] = mat[i][j];
        }
    }

    delete[] mat[0];
    delete[] mat;
}



// Public Functions
// ECB Section
/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @return uint8_t* 
 */
uint8_t * encryptECB(uint8_t * in, uint32_t inlen, uint8_t * key)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        encryptBlock(in + i, out + i, rkeys);
    }

    delete[] rkeys;

    return out;
}

/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @return uint8_t* 
 */
uint8_t * decryptECB(uint8_t * in, uint32_t inlen, uint8_t * key)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        decryptBlock(in + i, out + i, rkeys);
    }

    delete[] rkeys;

    return out;
}


// CBC Section

/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @param iv 
 * @return uint8_t* 
 */
uint8_t * encryptCBC(uint8_t * in, uint32_t inlen, uint8_t * key, uint8_t * iv)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *block = new uint8_t[blockBytesLen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        xorBlocks(block, in + i, block, blockBytesLen);
        encryptBlock(block, out + i, rkeys);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] block;
    delete[] rkeys;

    return out;
}


/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @param iv 
 * @return uint8_t* 
 */
uint8_t * decryptCBC(uint8_t * in, uint32_t inlen, uint8_t * key, uint8_t * iv)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *block = new uint8_t[blockBytesLen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        decryptBlock(in + i, out + i, rkeys);
        xorBlocks(block, out + i, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] block;
    delete[] rkeys;

    return out;
}


// CFB Section
/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @param iv 
 * @return uint8_t* 
 */
uint8_t * encryptCFB(uint8_t * in, uint32_t inlen, uint8_t * key, uint8_t * iv)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *block = new uint8_t[blockBytesLen];
    uint8_t *encryptedBlock = new uint8_t[blockBytesLen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        encryptBlock(block, encryptedBlock, rkeys);
        xorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] block;
    delete[] encryptedBlock;
    delete[] rkeys;

    return out;
}

/**
 * @brief 
 * 
 * @param in 
 * @param inlen 
 * @param key 
 * @param iv 
 * @return uint8_t* 
 */
uint8_t * decryptCFB(uint8_t * in, uint32_t inlen, uint8_t * key, uint8_t * iv)
{
    checkLength(inlen);
    uint8_t *out = new uint8_t[inlen];
    uint8_t *block = new uint8_t[blockBytesLen];
    uint8_t *encryptedBlock = new uint8_t[blockBytesLen];
    uint8_t *rkeys = new uint8_t[4 * AES_128_BKey_Size * (AES_128_ROUNDS + 1)];
    keyExpansion(key, rkeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inlen; i += blockBytesLen) {
        encryptBlock(block, encryptedBlock, rkeys);
        xorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] block;
    delete[] encryptedBlock;
    delete[] rkeys;

    return out;
}


/**
 * @brief 
 * 
 * @param text 
 * @return uint8_t* 
 */
uint8_t * convertString(const char * text)
{
    return ((uint8_t *) text);
}

/**
 * @brief 
 * Pad the text
 * 
 * @param text 
 * @return uint8_t* 
 */
uint8_t * pad(uint8_t * text, uint32_t len)
{
    if (len % 16 != 0)
    {
        uint8_t * out;
        uint32_t diff_len = (16 - (len%16));
        out = new uint8_t[len + diff_len];
        for (uint32_t i = 0; i < (len + diff_len); i++)
        {
            if (i < len)
            {
                out[i] = text[i];
            }
            else
            {
                out[i] = diff_len;
            }
        }
        return out;
    }

    else
    {
        return text;
    }
}


/**
 * @brief 
 * Remove the padding from the text
 * 
 * @param text 
 * @param len 
 * @return uint8_t* 
 */
uint8_t * removePad(uint8_t * text, uint32_t len)
{
    // Finding the padding value and dissasociating it from the rest of the text
    // if the padding exists
    if (len > 0)
    {
        // function definitions
        uint8_t * output;
        uint32_t actual_value = 0;

        // Padding Value extraction and testing
        if (text[len-1] > 0x00 && text[len-1] < 0x10)
        {
            actual_value = (uint32_t) text[len-1];

            // Padding value test
            if (text[len-actual_value-1] != actual_value)
            {
                actual_value = actual_value;
                // Clean up the values
                for (uint32_t i = 0; i < actual_value; i++)
                {
                    text[len-i-1] = 0x00; // Set the value to zero
                }
            }

            // Not an actual padding value
            else
            {
                return text;
            }
        }

        // No padding existing
        else
        {
            return text;
        }

        // now write the unpadded text
        output = new uint8_t[(len - actual_value)];
        for (uint32_t i =  0; i < (len - actual_value); i++)
        {
            output[i] = text[i];
        }
        output[(len - actual_value)] = 0x00; // End of string terminator

        // return the output
        return output;
    }

    // Length error detected (value 0 presented)
    else
    {
        return  text;
    }
}

/**
 * @brief 
 * 
 * @param text 
 * @return char* 
 */
char * toStr(uint8_t * text)
{
    return ((char *) text);
}
#endif