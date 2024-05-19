#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <DigitalKeySecureContext.h>
#include <x963kdf.h>
#include <utils.h>
#include <list>
#include <PN532.h>
#include <TLV8.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  std::vector<uint8_t> &reader_private_key;
  std::vector<uint8_t> readerEphPrivKey;
  std::list<hkIssuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  PN532& nfc;
  void Auth1_keys_generator(uint8_t *persistentKey, uint8_t *volatileKey);
  void Auth1_keying_material(uint8_t *keyingMaterial, const char *context, uint8_t *out, size_t outLen);

public:
  HKStdAuth(PN532& nfc, std::vector<uint8_t> &reader_private_key, std::vector<uint8_t> &readerEphPrivKey, std::list<hkIssuer_t> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_private_key(reader_private_key), readerEphPrivKey(readerEphPrivKey), issuers(issuers), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier), nfc(nfc) {/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
  std::tuple<hkIssuer_t *, hkEndpoint_t *, DigitalKeySecureContext, std::vector<uint8_t>, KeyFlow> attest();
};