#pragma once
#include "HomeKey.h"
#include <nvs.h>

class HKAuthenticationContext
{
private:
  const char *TAG = "HKAuthCtx";
  readerData_t &readerData;
  nvs_handle &savedData;
  std::vector<uint8_t> readerEphX;
  std::vector<uint8_t> readerEphPrivKey;
  std::vector<uint8_t> readerEphPubKey;
  std::vector<uint8_t> endpointEphPubKey;
  std::vector<uint8_t> endpointEphX;
  const std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)> &nfc;
  std::vector<uint8_t> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key);
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
public:
  HKAuthenticationContext(const std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)> &nfc, readerData_t &readerData, nvs_handle &savedData);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, KeyFlow> authenticate(KeyFlow);
};