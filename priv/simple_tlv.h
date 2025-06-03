#pragma once
#include <vector>
#include <cstdint>
std::vector<unsigned char> simple_tlv(unsigned char tag, const unsigned char* value, size_t valLength, unsigned char* out = NULL, size_t* olen = NULL);
