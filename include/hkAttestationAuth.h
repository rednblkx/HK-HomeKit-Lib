#pragma once
#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <list>
#include <vector>
#include <BerTlv.h>
#include <DigitalKeySecureContext.h>
#include <x963kdf.h>
#include <ndef.h>
#include <utils.h>
#include <ISO18013SecureContext.h>
#include <sodium/crypto_sign_ed25519.h>
#include <freertos/FreeRTOS.h>
#include <cbor.h>
#include <jsoncons/json.hpp>
#include <jsoncons_ext/cbor/cbor.hpp>
#include <functional>

using namespace jsoncons;
using namespace CommonCryptoUtils;
using namespace utils;

class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  std::list<hkIssuer_t> &issuers;
  std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc;
  std::vector<uint8_t> attestation_exchange_common_secret;
  DigitalKeySecureContext &DKSContext;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<hkIssuer_t*, std::vector<uint8_t>> verify(std::vector<uint8_t> &decryptedCbor);

public:
  HKAttestationAuth(std::list<hkIssuer_t> &issuers, DigitalKeySecureContext &context, std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc) : issuers(issuers), nfc(nfc), DKSContext(context){/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
  std::tuple<hkIssuer_t *, std::vector<uint8_t>, KeyFlow> attest();
};
