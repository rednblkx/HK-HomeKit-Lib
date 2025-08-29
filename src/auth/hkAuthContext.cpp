#include <hkAuthContext.h>
#include "CommonCryptoUtils.h"
#include "HomeKey.h"
#include "fmt/ranges.h"
#include "hkFastAuth.h"
#include "hkStdAuth.h"
#include "hkAttestationAuth.h"
#include "simple_tlv.h"
#include "logging.h"
#include <esp_random.h>
#include <mbedtls/sha1.h>
#include <chrono>
#include <TLV8.hpp>

/**
 * The HKAuthenticationContext constructor generates an ephemeral key for the reader and initializes
 * core variables
 *
 * @param nfc The `nfc` parameter is a function pointer that points to a
 * function responsible for exchanging data with an NFC device. It takes input data, its length, and
 * returns a response along with the response length.
 * @param readerData The `readerData` parameter is a reference to an object of type
 * `readerData_t`.
 * @param savedData The `savedData` parameter in the `HKAuthenticationContext` constructor is of type
 * `nvs_handle`, which is a handle to a Non-Volatile Storage (NVS) namespace in ESP-IDF
 * (Espressif IoT Development Framework). This handle is used to access and manipulate data stored.
 */
HKAuthenticationContext::HKAuthenticationContext(const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc, readerData_t &readerData, const std::function<void(const readerData_t&)> &save_cb) : readerData(readerData), nfc(nfc), save_cb(save_cb), transactionIdentifier(16)
{
  // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = CommonCryptoUtils::generateEphemeralKey();
  readerEphPrivKey.swap(std::get<0>(readerEphKey));
  readerEphPubKey.swap(std::get<1>(readerEphKey));
  esp_fill_random(transactionIdentifier.data(), 16);
  readerIdentifier.reserve(readerData.reader_gid.size() + readerData.reader_id.size());
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_gid.begin(), readerData.reader_gid.end());
  readerIdentifier.insert(readerIdentifier.end(), readerData.reader_id.begin(), readerData.reader_id.end());
  readerEphX = CommonCryptoUtils::get_x(readerEphPubKey);
  auto stopTime = std::chrono::high_resolution_clock::now();
  LOG(I, "Initialization Time: %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
}

std::vector<uint8_t> HKAuthenticationContext::getHashIdentifier(const std::vector<uint8_t>& key) {
  LOG(V, "Key: %s, Length: %d", fmt::format("{:02X}", fmt::join(key, "")).c_str(), key.size());
  std::vector<unsigned char> hashable;
  hashable.insert(hashable.end(), key.begin(), key.end());
  LOG(V, "Hashable: %s", fmt::format("{:02X}", fmt::join(hashable, "")).c_str());
  std::vector<uint8_t> hash(32);
  mbedtls_sha1(&hashable.front(), hashable.size(), hash.data());
  LOG(V, "HashIdentifier: %s", fmt::format("{:02X}", fmt::join(hash, "")).c_str());
  return hash;
}

/**
 * The function `authenticate` in the `HKAuthenticationContext` class processes authentication data and
 * returns the issuer and endpoint IDs along with the authentication flow type.
 * 
 * @param hkFlow The `hkFlow` parameter in the `authenticate` function is an integer that determines
 * the type of HomeKey flow to be used for authentication. It can have the following values defined in
 * the `KeyFlow` enum: kFlowFAST, kFlowSTANDARD and kFlowATTESTATION
 * 
 * @return A tuple containing the matching `issuer_id` and `ep_id`, and the successful flow from
 * the enum `KeyFlow`.
 */
std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, KeyFlow> HKAuthenticationContext::authenticate(KeyFlow hkFlow){
  auto startTime = std::chrono::high_resolution_clock::now();
  uint8_t prot_v_data[2] = {0x02, 0x0};

  std::vector<uint8_t> fastTlv(sizeof(prot_v_data) + readerEphPubKey.size() + transactionIdentifier.size() + readerIdentifier.size() + 8);
  size_t len = 0;
  simple_tlv(0x5C, prot_v_data, sizeof(prot_v_data), fastTlv.data(), &len);

  simple_tlv(0x87, readerEphPubKey.data(), readerEphPubKey.size(), fastTlv.data() + len, &len);

  simple_tlv(0x4C, transactionIdentifier.data(), transactionIdentifier.size(), fastTlv.data() + len, &len);

  simple_tlv(0x4D, readerIdentifier.data(), readerIdentifier.size(), fastTlv.data() + len, &len);
  std::vector<uint8_t> apdu{0x80, 0x80, 0x01, 0x01, (uint8_t)len};
  apdu.insert(apdu.begin() + 5, fastTlv.begin(), fastTlv.end());
  std::vector<uint8_t> response;
  LOG(D, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), fmt::format("{:02X}", fmt::join(apdu, "")).c_str());
  nfc(apdu, response, false);
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, response.data(), response.size(), ESP_LOG_VERBOSE);
  LOG(D, "Auth0 Response Length: %d, DATA: %s", response.size(), fmt::format("{:02X}", fmt::join(response, "")).c_str());
  if (response.size() > 64 && response[0] == 0x86) {
    TLV8 Auth0Res;
    Auth0Res.parse(response.data(), response.size());
    tlv_it pubkey = Auth0Res.find(kEndpoint_Public_Key);
    endpointEphPubKey = pubkey->value;
    endpointEphX = CommonCryptoUtils::get_x(endpointEphPubKey);
    hkIssuer_t *foundIssuer = nullptr;
    hkEndpoint_t *foundEndpoint = nullptr;
    std::vector<uint8_t> persistentKey;
    KeyFlow flowUsed = kFlowFailed;
    if (hkFlow == kFlowFAST) {
      tlv_it crypt = Auth0Res.find(kAuth0_Cryptogram);
      std::vector<uint8_t> encryptedMessage = crypt->value;
      auto fastAuth = HKFastAuth(readerData.reader_pk_x, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest(encryptedMessage);
      if (std::get<1>(fastAuth) != nullptr && (flowUsed = std::get<2>(fastAuth)) == kFlowFAST)
      {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        LOG(D, "Endpoint %s Authenticated via FAST Flow", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_id, "")).c_str());
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = HKStdAuth(nfc, readerData.reader_sk, readerEphPrivKey, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest();
      if(std::get<1>(stdAuth) != nullptr){
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if ((flowUsed = std::get<4>(stdAuth)) == kFlowSTANDARD)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_id, "")).c_str());
          persistentKey = std::get<3>(stdAuth);
          foundEndpoint->endpoint_prst_k = persistentKey;
          LOG(V, "New Persistent Key: %s", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_prst_k, "")).c_str());
        }
      }
      if (std::get<4>(stdAuth) == kFlowNext || hkFlow == kFlowATTESTATION) {
        auto attestation = HKAttestationAuth(readerData.issuers, std::get<2>(stdAuth), nfc).attest();
        if ((flowUsed = std::get<KeyFlow>(attestation)) == kFlowATTESTATION) {
          hkEndpoint_t endpoint;
          foundIssuer = std::get<0>(attestation);
          std::vector<uint8_t> devicePubKey = std::get<1>(attestation);
          std::vector<uint8_t> deviceKeyX = CommonCryptoUtils::get_x(std::get<1>(attestation));
          endpoint.endpoint_pk_x = deviceKeyX;
          std::vector<uint8_t> eId = getHashIdentifier(devicePubKey);
          endpoint.endpoint_id = std::vector<uint8_t>{eId.begin(), eId.begin() + 6};
          endpoint.endpoint_pk = devicePubKey;
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", fmt::format("{:02X}", fmt::join(endpoint.endpoint_id, "")).c_str());
          persistentKey = std::get<3>(stdAuth);
          endpoint.endpoint_prst_k = persistentKey;
          LOG(V, "New Persistent Key: %s", fmt::format("{:02X}", fmt::join(endpoint.endpoint_prst_k, "")).c_str());
          foundEndpoint = &(*foundIssuer->endpoints.emplace(foundIssuer->endpoints.end(),endpoint));
        }
      }
      if(flowUsed >= kFlowSTANDARD && persistentKey.size() > 0){
        save_cb(readerData);
      }
    }
    if(foundEndpoint != nullptr && flowUsed != kFlowFailed) {
      std::vector<uint8_t> cmdFlowStatus;
      if (flowUsed < kFlowATTESTATION)
      {
        cmdFlowStatus = commandFlow(kCmdFlowSuccess);
        LOG(D, "CONTROL FLOW RESPONSE: %s, Length: %d", fmt::format("{:02X}", fmt::join(cmdFlowStatus, "")).c_str(), cmdFlowStatus.size());
      }
      if (flowUsed == kFlowATTESTATION || cmdFlowStatus.data()[0] == 0x90)
      {
        LOG(I, "Endpoint authenticated, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, flowUsed);
      } else {
        LOG(E, "Control Flow Response not 0x90!, %s", fmt::format("{:02X}", fmt::join(cmdFlowStatus, "")).c_str());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, kFlowFailed);
      }
    } else commandFlow(kCmdFlowFailed);
  }
  commandFlow(kCmdFlowFailed);
  LOG(E, "Response not valid, something went wrong!");
  return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>(), kFlowFailed);
}

/**
 * The function `HKAuthenticationContext::commandFlow` sends the command flow status APDU command
 * and returns the response.
 * 
 * @param status The parameter "status" is of type "CommandFlowStatus"
 * 
 * @return a std::vector<uint8_t> object, which contains the received response
 */
std::vector<uint8_t> HKAuthenticationContext::commandFlow(CommandFlowStatus status)
{
  std::vector<uint8_t> apdu = {0x80, 0x3c, static_cast<uint8_t>(status), status == kCmdFlowAttestation ? (uint8_t)0xa0 : (uint8_t)0x0};
  std::vector<uint8_t> cmdFlowRes(3);
  LOG(D, "APDU: %s, Length: %d", fmt::format("{:02X}", fmt::join(apdu, "")).c_str(), apdu.size());
  nfc(apdu, cmdFlowRes, false);
  return cmdFlowRes;
}
