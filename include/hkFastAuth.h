#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <BerTlv.h>
#include <utils.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  uint8_t &reader_key_X;
  std::list<homeKeyIssuer::issuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  void Auth0_keying_material(const char *context, const uint8_t *ePub_X, const uint8_t *keyingMaterial, uint8_t *out, size_t outLen);
  std::tuple<homeKeyIssuer::issuer_t *, homeKeyEndpoint::endpoint_t *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  std::tuple<homeKeyIssuer::issuer_t *, homeKeyEndpoint::endpoint_t *,homeKeyReader::KeyFlow> attest(std::vector<uint8_t> &encryptedMessage);
  HKFastAuth(uint8_t &reader_key_X, std::list<homeKeyIssuer::issuer_t> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_key_X(reader_key_X), issuers(issuers), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier){};
};