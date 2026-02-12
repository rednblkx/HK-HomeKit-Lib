#include "HomeKey.h"
#include "DigitalKeySecureContext.h"
#include "hkAuthParams.h"
#include <functional>

class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  HKAuthParams &params;
  std::vector<uint8_t> attestation_exchange_common_secret;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<hkIssuer_t*, std::vector<uint8_t>> verify(std::vector<uint8_t>& decryptedCbor);

public:
  HKAttestationAuth(HKAuthParams &params);
  std::tuple<hkIssuer_t *, std::vector<uint8_t>, KeyFlow> attest();
};
