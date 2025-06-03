#pragma once
#include <cstdint>
#include <vector>
#include <tuple>

namespace CommonCryptoUtils
{
  void get_shared_key(const std::vector<uint8_t> &key1, const std::vector<uint8_t> &key2, uint8_t *outBuf, size_t oLen);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> generateEphemeralKey();
  std::vector<uint8_t> signSharedInfo(const uint8_t *data, const size_t len, const uint8_t *privateKey, const size_t keyLen);
  std::vector<uint8_t> get_x(std::vector<uint8_t> &pubKey);
  int esp_rng(void *, uint8_t *buf, size_t len);
}