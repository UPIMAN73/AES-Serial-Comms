#ifndef DUMPMEM_HPP_
#define DUMPMEM_HPP_

#include <Arduino.h>

#define MAX_ALLOWABLE_PTR_SIZE 512

#define DESIRED_ADDRESS 0x0100

#define MMIO(addr) *((char *) addr)

void dumpAll(void const * at, uint16_t size)
{
  while (size > 0)
  {
    //
    Serial.print("0x");
    Serial.print((unsigned long)at < 0x10 ? "000" : (unsigned long)at<0x100 ? "00" : (unsigned long)at<0x1000 ? "0" : "");
    Serial.print((unsigned long)at, HEX);
    Serial.print(":\t");

    for (uint16_t c = 0; c < 16; c++)
    {
      if (c == 8)
      {
        Serial.write(" ");
      }
      
      if (size - c > 0)
      {
        void * addr = (void *) ((uint16_t) at + c);
        uint8_t v = MMIO(addr);
        Serial.write((v>=32&&v<='z'/*&&v!=0xBF*/)?v:'.');
      }
      else
      {
        Serial.write(" ");
      }
    }
    Serial.print("\t");
    for (uint16_t c = 0; c < 16 && size; c++, size--)
    {
      if (c == 8)
      {
        Serial.write(" ");
      }
      
      at = (void *)((uint16_t)at + 1);
      uint8_t v = MMIO(at);
      Serial.print(v<16?"0":"");
      Serial.print(v,HEX);
      Serial.write(' ');
    }
    Serial.println();
  }
}

#endif