#pragma once
#include "HomeKey.h"
#include <cstdint>
#include <functional>
#include <vector>

class HKAuthenticationContext
{
private:
  const char *TAG = "HKAuthCtx";
  readerData_t &readerData;
  std::vector<uint8_t> readerEphX;
  std::vector<uint8_t> readerEphPrivKey;
  std::vector<uint8_t> readerEphPubKey;
  std::vector<uint8_t> endpointEphPubKey;
  std::vector<uint8_t> endpointEphX;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc;
  const std::function<void(const readerData_t&)> &save_cb;
  std::vector<uint8_t> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key);
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
public:
  HKAuthenticationContext(const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc, readerData_t &readerData, const std::function<void(const readerData_t&)> &save_cb);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, KeyFlow> authenticate(KeyFlow);
};
