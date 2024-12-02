#include "HomeKey.h"
#include "DigitalKeySecureContext.h"

using json = nlohmann::json;

class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  std::vector<hkIssuer_t> &issuers;
  std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc;
  std::vector<uint8_t> attestation_exchange_common_secret;
  DigitalKeySecureContext &DKSContext;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<hkIssuer_t*, std::vector<uint8_t>> verify(std::vector<uint8_t>& decryptedCbor);

public:
  HKAttestationAuth(std::vector<hkIssuer_t> &issuers, DigitalKeySecureContext &context, std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)>& nfc) : issuers(issuers), nfc(nfc), DKSContext(context){/* esp_log_level_set(TAG, ESP_LOG_VERBOSE); */};
  std::tuple<hkIssuer_t *, std::vector<uint8_t>, KeyFlow> attest();
};
