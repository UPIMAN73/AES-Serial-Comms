/**
 * @file aesmanagement.hpp
 * @author Joshua Calzadillas (upiman73@github.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-26
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef AESMANAGEMENT_HPP_
#define AESMANAGEMENT_HPP_

#include "aes.hpp"

// AES Default Values
// Change the value of the KEY and the IV
uint8_t   KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t    IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
struct AES_ctx ctx;

// Functions that are associated with the AES padding
uint8_t * padValues(uint8_t * address, uint32_t length);
uint8_t * padValues(char    * address, uint32_t length);
uint8_t * removePad(uint8_t * address, uint32_t length);
uint8_t * removePad(char    * address, uint32_t length);

/**
 * @brief 
 * 
 * @param address 
 * @param length 
 */
uint8_t * padValues(uint8_t * address, uint32_t length)
{
    // String length check
    if (length % 16 != 0)
    {
        // calculate padding value to append to the end of the text
        uint8_t value = 16 - (length % 16); // calculate the required padding size
        uint8_t * temp = new uint8_t[length + value];
        for (uint32_t i = 0; i < length + value; i++)
        {
            if (i < length)
            {
                temp[i] = address[i];
            }
            else
            {
                temp[i] = value;
            }
        }
        return temp;
    }

    else
    {
        return address;
    }
}

/**
 * @brief 
 * 
 * @param address 
 * @param length 
 */
uint8_t * padValues(char * address, uint32_t length)
{
    return padValues((uint8_t *) address, length);
}

/**
 * @brief 
 * 
 * @param address 
 * @param length 
 * @return uint8_t* 
 */
uint8_t * removePad(uint8_t * address, uint32_t length)
{
    // if the padding value is there
    if (address[length-1] > 0x00 && address[length-1] < 0x10)
    {
        // value of the padding
        uint8_t value = address[length-1];
        if (value == address[length - value] && value != address[length - value - 1])
        {
            // Cleaning up the address values
            for (uint32_t i = length - value; i < length; i++)
            {
                address[i] = 0x00;
            }
        }
    }
    return address;
}

/**
 * @brief 
 * 
 * @param address 
 * @param length 
 */
uint8_t * removePad(char * address, uint32_t length)
{
    // convert to the allowable function
    return removePad((uint8_t *) address, length);
}

#endif