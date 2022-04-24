#include <Arduino.h>
#include "AES/aes.hpp"

#define BUAD_RATE       9600
#define MESSAGE_TEXT    "ARDUINO MKRWAN 1300"
#define ROOT_KEY        "0123456789abcdef"
#define IV_KEY          "0000000000000000"


void setup() {
  // put your setup code here, to run once:
  Serial.begin(BUAD_RATE);

  Serial.println(MESSAGE_TEXT);

  // AES Definitions
  uint8_t * plainText = convertString(MESSAGE_TEXT);
  uint8_t * rkey = convertString(ROOT_KEY);

  // CBC Encryption
  uint8_t * eout = encryptCBC(plainText, strlen((char *) plainText), rkey, convertString(IV_KEY));
  Serial.print("\nEncrypted Text: ");
  Serial.println(String((char *) eout));
}

void loop() {
  // put your main code here, to run repeatedly:
}