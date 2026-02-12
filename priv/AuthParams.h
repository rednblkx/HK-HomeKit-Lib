#pragma once
#include <array>
#include <functional>
#include <vector>
#include "DDKReaderData.h"
#include "DigitalKeySecureContext.h"

struct DDKAuthParams {
  DigitalKeyType type;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &reader_pk_x;
  std::vector<uint8_t> &readerEphX;
  std::vector<uint8_t> &endpointEphPubKey;
  std::vector<uint8_t> &endpointEphX;
  std::vector<uint8_t> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  std::vector<uint8_t> &aliroFCI;
  std::array<uint8_t, 2> &version;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)>& nfc;
  
  std::vector<uint8_t> *reader_private_key{};
  std::vector<uint8_t> *readerEphPrivKey{};
  std::vector<uint8_t> *readerEphPubKey{};
  std::array<uint8_t, 2> &flags;
  DigitalKeySecureContext *context = nullptr;
};
