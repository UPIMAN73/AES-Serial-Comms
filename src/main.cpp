#include <Arduino.h>
// #include 
#include "dumpmem.hpp"
#include "AES/aes.hpp"

#define BUAD_RATE       9600
#define MESSAGE_TEXT    "ARDUINO MKRWAN 1300"
#define ROOT_KEY        "0123456789abcdef"
#define IV_KEY          "0000000000000000"


void setup() 
{
  // put your setup code here, to run once:
  while (!Serial)
  {
    Serial.begin(BUAD_RATE);
    delay(10);
  }

  Serial.println(MESSAGE_TEXT);
  Serial.println(String(MESSAGE_TEXT).length());

  // AES Definitions
  uint8_t * plainText = convertString(MESSAGE_TEXT);
  uint8_t * rkey = convertString(ROOT_KEY);
  uint8_t * iv = convertString(IV_KEY);
  // uint8_t * padded = pad(plainText, strlen(toStr(plainText)));
  

  // CBC Encryption
  uint8_t * eout = encryptECB(plainText, strlen(toStr(plainText)), rkey);
  // uint8_t * eout = encryptCBC(padded, strlen(toStr(padded)), rkey, iv);
  Serial.print("\nEncrypted Text: \n");
  Serial.println(strlen(toStr(eout)));
  Serial.println(toStr(eout));

  // CBC Decryption
  uint8_t * dout = decryptECB(eout, strlen(toStr(eout)), rkey);
  // uint8_t * dout = decryptCBC(eout, strlen(toStr(eout)), rkey, iv);
  dout = removePad(dout, strlen(toStr(dout)));
  String decryptedText = String(toStr(dout));
  Serial.print("\n\nDecrypted Text: \n");
  Serial.println(decryptedText.length());
  Serial.println(decryptedText);

  // dumpAll((void*) DESIRED_ADDRESS, (0x08FF - DESIRED_ADDRESS));
  Serial.println(" ");
  Serial.println(" ");
  dumpAll(plainText, strlen(toStr(plainText)) + 8);
  Serial.println(" ");
  dumpAll(&decryptedText, decryptedText.length() + 8);
  // dumpAll(toStr(padded), strlen(toStr(padded)) + 8);
}

void loop() {
  // put your main code here, to run repeatedly:
}