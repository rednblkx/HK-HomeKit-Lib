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
#include <cJSON.h>
#include <cbor.h>
#include <PN532.h>

using namespace CommonCryptoUtils;
using namespace utils;
class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  std::list<HomeKeyData_KeyIssuer> &issuers;
  PN532& nfc;
  std::vector<uint8_t> attestation_exchange_common_secret;
  DigitalKeySecureContext &DKSContext;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<HomeKeyData_KeyIssuer*, std::vector<uint8_t>, std::vector<uint8_t>> verify(std::vector<uint8_t> &decryptedCbor);

public:
  HKAttestationAuth(std::list<HomeKeyData_KeyIssuer> &issuers, DigitalKeySecureContext &context, PN532& nfc) : issuers(issuers), nfc(nfc), DKSContext(context){};
  std::tuple<std::tuple<HomeKeyData_KeyIssuer *, std::vector<uint8_t>, std::vector<uint8_t>>, KeyFlow> attest();
};
