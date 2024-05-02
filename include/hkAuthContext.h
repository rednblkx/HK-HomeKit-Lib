#pragma once
#include <tuple>
#include "HomeKey.h"
#include <HomeKeyData.pb.h>
#include <DigitalKeySecureContext.h>
#include <nvs.h>
#include <CommonCryptoUtils.h>
#include <chrono>
#include <hkFastAuth.h>
#include <hkStdAuth.h>
#include <hkAttestationAuth.h>
#include <BerTlv.h>
#include <PN532.h>

using namespace CommonCryptoUtils;
using namespace utils;

class HKAuthenticationContext
{
private:
  const char *TAG = "HKAuthCtx";
  HomeKeyData_ReaderData &readerData;
  nvs_handle &savedData;
  std::vector<uint8_t> readerEphX;
  std::vector<uint8_t> readerEphPrivKey;
  std::vector<uint8_t> readerEphPubKey;
  std::vector<uint8_t> endpointEphPubKey;
  std::vector<uint8_t> endpointEphX;
  PN532& nfc;
  std::vector<uint8_t> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);

public:
  HKAuthenticationContext(PN532 &nfc, HomeKeyData_ReaderData &readerData, nvs_handle &savedData);
  std::tuple<uint8_t *, uint8_t *, KeyFlow> authenticate(KeyFlow);
};