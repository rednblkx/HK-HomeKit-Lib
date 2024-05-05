#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <HomeKeyData.pb.h>
#include <list>
#include <BerTlv.h>
#include <utils.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  uint8_t &reader_key_X;
  HomeKeyData_KeyIssuer* issuers;
  size_t issuers_count = 0;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  void Auth0_keying_material(const char *context, const uint8_t *ePub_X, const uint8_t *keyingMaterial, uint8_t *out, size_t outLen);
  std::tuple<HomeKeyData_KeyIssuer *, HomeKeyData_Endpoint *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  std::tuple<HomeKeyData_KeyIssuer *, HomeKeyData_Endpoint *, KeyFlow> attest(std::vector<uint8_t> &encryptedMessage);
  HKFastAuth(pb_byte_t &reader_key_X, HomeKeyData_KeyIssuer *issuers, size_t issuers_count, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_key_X(reader_key_X), issuers(issuers), issuers_count(issuers_count), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier){/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
};