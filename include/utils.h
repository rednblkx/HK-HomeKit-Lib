#pragma once
#include <cstdint>
#include <string>
#include <mbedtls/base64.h>
#include <algorithm>
#include <vector>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <string.h>
#include <mbedtls/error.h>
#include <esp_log.h>
#include <sstream>
#include <iomanip>
#define LOG(x, format, ...) ESP_LOG##x(TAG, "%s > " format, __FUNCTION__ __VA_OPT__(, ) __VA_ARGS__)
namespace utils
{
  std::string int_to_hex(int i);
  void pack(const uint8_t *buf, size_t buflen, uint8_t *out, size_t *olen);
  std::string bufToHexString(const uint8_t *buf, size_t len, bool ignoreLevel = false);
  std::string bufToHexString(const uint16_t *buf, size_t len, bool ignoreLevel = false);
  std::vector<uint8_t> encodeB64(const uint8_t *src, size_t len);
  std::vector<uint8_t> decodeB64(const char *src);
  std::vector<uint8_t> getHashIdentifier(const uint8_t *key, size_t len, bool keyIdentifier);
  std::vector<unsigned char> simple_tlv(unsigned char tag, const unsigned char *value, size_t valLength, unsigned char *out = NULL, size_t *olen = NULL);
};