#pragma once
#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <mbedtls/hkdf.h>
#include <DigitalKeySecureContext.h>
#include <x963kdf.h>
#include <utils.h>
#include <list>
#include <TLV8.h>
#include <functional>

using namespace CommonCryptoUtils;
using namespace utils;

class HKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  std::vector<uint8_t> &reader_private_key;
  std::vector<uint8_t> &readerEphPrivKey;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc;
  void Auth1_keys_generator(uint8_t *persistentKey, uint8_t *volatileKey);
  void Auth1_keying_material(uint8_t *keyingMaterial, const char *context, uint8_t *out, size_t outLen);

public:
  HKStdAuth(std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc, std::vector<uint8_t> &reader_private_key, std::vector<uint8_t> &readerEphPrivKey, std::vector<hkIssuer_t> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_private_key(reader_private_key), readerEphPrivKey(readerEphPrivKey), issuers(issuers), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier), nfc(nfc) {/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
  std::tuple<hkIssuer_t *, hkEndpoint_t *, DigitalKeySecureContext, std::vector<uint8_t>, KeyFlow> attest();
};