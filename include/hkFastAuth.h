#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <list>
#include <utils.h>
#include <mbedtls/hkdf.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  std::vector<uint8_t> &reader_key_X;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  void Auth0_keying_material(const char *context, const std::vector<uint8_t> &ePub_X, const std::vector<uint8_t> &keyingMaterial, uint8_t *out, size_t outLen);
  std::tuple<hkIssuer_t *, hkEndpoint_t *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  std::tuple<hkIssuer_t *, hkEndpoint_t *, KeyFlow> attest(std::vector<uint8_t> &encryptedMessage);
  HKFastAuth(std::vector<uint8_t> &reader_pk_x, std::vector<hkIssuer_t> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_key_X(reader_pk_x), issuers(issuers), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier){/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
};