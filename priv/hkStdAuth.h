#pragma once
#include "HomeKey.h"
#include "DigitalKeySecureContext.h"
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

class HKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
	DigitalKeyType type;
  std::vector<uint8_t> &reader_private_key;
  std::vector<uint8_t> &readerEphPrivKey;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  std::vector<uint8_t> &aliroFCI;
  std::array<uint8_t, 2> &version;
	std::vector<uint8_t> &readerPkX;
	std::vector<uint8_t> *epPkX;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)>& nfc;
	template <typename Container>
  void Auth1_keying_material(std::array<uint8_t,32> &keyingMaterial, std::string_view context, Container &out);

public:
  HKStdAuth(DigitalKeyType type, const std::function<bool(std::vector<uint8_t> &, std::vector<uint8_t> &, bool)> &nfc,
            std::vector<uint8_t> &reader_private_key, std::vector<uint8_t> &readerEphPrivKey,
            std::vector<hkIssuer_t> &issuers, std::vector<uint8_t> &readerEphX, std::vector<uint8_t> &endpointEphPubKey,
            std::vector<uint8_t> &endpointEphX, std::vector<uint8_t> &transactionIdentifier,
            std::vector<uint8_t> &readerIdentifier, std::vector<uint8_t> &aliroFci,
            std::array<uint8_t,2> &version, std::vector<uint8_t> &readerPkX);
  std::tuple<hkIssuer_t *, hkEndpoint_t *, std::unique_ptr<DigitalKeySecureContext>, std::array<uint8_t,32>, KeyFlow> attest();
};
