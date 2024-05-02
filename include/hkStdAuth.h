#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <HomeKeyData.pb.h>
#include <DigitalKeySecureContext.h>
#include <x963kdf.h>
#include <BerTlv.h>
#include <utils.h>
#include <list>
#include <PN532.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  uint8_t &reader_private_key;
  std::vector<uint8_t> readerEphPrivKey;
  std::list<HomeKeyData_KeyIssuer> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  PN532& nfc;
  void Auth1_keys_generator(uint8_t *persistentKey, uint8_t *volatileKey);
  void Auth1_keying_material(uint8_t *keyingMaterial, const char *context, uint8_t *out, size_t outLen);

public:
  HKStdAuth(PN532& nfc, pb_byte_t &reader_private_key, std::vector<uint8_t> &readerEphPrivKey, std::list<HomeKeyData_KeyIssuer> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier, std::vector<uint8_t> &readerIdentifier) : reader_private_key(reader_private_key), readerEphPrivKey(readerEphPrivKey), issuers(issuers), readerEphX(readerEphX), endpointEphPubKey(endpointEphPubKey), endpointEphX(endpointEphX), transactionIdentifier(transactionIdentifier), readerIdentifier(readerIdentifier), nfc(nfc) {};
  std::tuple<HomeKeyData_KeyIssuer *, HomeKeyData_Endpoint *, DigitalKeySecureContext, std::vector<uint8_t>, KeyFlow> attest();
};