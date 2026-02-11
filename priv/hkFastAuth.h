#include <array>
#include <sys/types.h>

#include "HomeKey.h"

class HKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  DigitalKeyType type;
  std::vector<uint8_t> &reader_key_X;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t>& readerIdentifier;
  std::vector<uint8_t>& aliroFCI;
  std::array<uint8_t,2> &version;
  std::array<uint8_t,2> &flags;
  void Auth0_keying_material(const char* context, const std::vector<uint8_t>& ePubX, const std::vector<uint8_t>& keyingMaterial, uint8_t* out, size_t outLen);
  std::tuple<hkIssuer_t *, hkEndpoint_t *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  std::tuple<hkIssuer_t *, hkEndpoint_t *, KeyFlow> attest(std::vector<uint8_t> &encryptedMessage);
  HKFastAuth(DigitalKeyType type,std::vector<uint8_t> &reader_pk_x, std::vector<hkIssuer_t> &issuers, std::vector<uint8_t> &readerEphX,
             std::vector<uint8_t> &endpointEphPubKey, std::vector<uint8_t> &endpointEphX,
             std::vector<uint8_t> &transactionIdentifier,
             std::vector<uint8_t> &readerIdentifier,
             std::vector<uint8_t> &aliroFci,
             std::array<uint8_t,2> &version,
             std::array<uint8_t,2> &flags);
};
