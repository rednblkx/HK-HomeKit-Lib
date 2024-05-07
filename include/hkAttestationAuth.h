#include <CommonCryptoUtils.h>
#include <tuple>
#include "HomeKey.h"
#include <HomeKeyData.pb.h>
#include <list>
#include <vector>
#include <BerTlv.h>
#include <DigitalKeySecureContext.h>
#include <x963kdf.h>
#include <ndef.h>
#include <utils.h>
#include <ISO18013SecureContext.h>
#include <sodium/crypto_sign_ed25519.h>
#include <PN532.h>
#include <freertos/FreeRTOS.h>
#include <cbor.h>
#include <jsoncons/json.hpp>
#include <jsoncons_ext/cbor/cbor.hpp>

using namespace jsoncons;
using namespace CommonCryptoUtils;
using namespace utils;

class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  HomeKeyData_KeyIssuer *issuers;
  size_t issuers_count = 0;
  PN532& nfc;
  std::vector<uint8_t> attestation_exchange_common_secret;
  DigitalKeySecureContext &DKSContext;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<HomeKeyData_KeyIssuer*, std::vector<uint8_t>> verify(std::vector<uint8_t> &decryptedCbor);

public:
  HKAttestationAuth(HomeKeyData_KeyIssuer *issuers, size_t issuers_count, DigitalKeySecureContext &context, PN532& nfc) : issuers(issuers), issuers_count(issuers_count), nfc(nfc), DKSContext(context){/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
  std::tuple<HomeKeyData_KeyIssuer *, std::vector<uint8_t>, KeyFlow> attest();
};
