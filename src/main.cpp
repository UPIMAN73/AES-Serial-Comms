/**
 * @file main.cpp
 * @author Joshua Calzadillas (upiman73@github.com)
 * @brief 
 * @version 0.1
 * @date 2022-04-26
 * 
 * 
 */
#include <Arduino.h>
#include "AES/aesmanagement.hpp"

#define BUAD_RATE       9600


static void phex(uint8_t* str); // Print Hex


/**
 * @brief 
 * Setup function runs the code once
 * 
 */
void setup() 
{
  // put your setup code here, to run once:
  while (!Serial)
  {
    Serial.begin(BUAD_RATE);
    delay(10);
  }

  // AES Settings
  AES_init_ctx_iv(&ctx, KEY, IV); // initilizing the CTX environment
}

/**
 * @brief 
 * Loops function loops the code
 * 
 */
void loop() {
  // put your main code here, to run repeatedly:
}

// prints string as hex
static void phex(uint8_t* str)
{
    uint8_t len = 16;

    unsigned char i;
    for (i = 0; i < len; ++i)
        Serial.print(str[i], HEX);
    Serial.print("\n");
}
