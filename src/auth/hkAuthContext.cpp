#include <hkAuthContext.h>

/**
 * The HKAuthenticationContext constructor generates an ephemeral key for the reader and initializes
 * core variables
 *
 * @param nfcInDataExchange The `nfcInDataExchange` parameter is a function pointer that points to a
 * function responsible for exchanging data with an NFC device. It takes input data, its length, and
 * returns a response along with the response length.
 * @param readerData The `readerData` parameter is a reference to an object of type
 * `homeKeyReader::readerData_t`.
 * @param savedData The `savedData` parameter in the `HKAuthenticationContext` constructor is of type
 * `nvs_handle`, which is a handle to a Non-Volatile Storage (NVS) namespace in ESP-IDF
 * (Espressif IoT Development Framework). This handle is used to access and manipulate data stored.
 */
HKAuthenticationContext::HKAuthenticationContext(bool (*nfcInDataExchange)(uint8_t *data, size_t lenData, uint8_t *res, uint8_t *resLen), homeKeyReader::readerData_t &readerData, nvs_handle &savedData) : readerData(readerData), savedData(savedData), nfcInDataExchange(nfcInDataExchange)
{
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = generateEphemeralKey();
  readerEphPrivKey = std::move(std::get<0>(readerEphKey));
  readerEphPubKey = std::move(std::get<1>(readerEphKey));
  transactionIdentifier.resize(16);
  transactionIdentifier.reserve(16);
  esp_fill_random(transactionIdentifier.data(), 16);
  readerIdentifier.reserve(sizeof(readerData.reader_identifier) + sizeof(readerData.identifier));
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_identifier, readerData.reader_identifier + sizeof(readerData.reader_identifier));
  readerIdentifier.insert(readerIdentifier.end(), readerData.identifier, readerData.identifier + sizeof(readerData.identifier));
  readerEphX = std::move(get_x(readerEphPubKey));
  auto stopTime = std::chrono::high_resolution_clock::now();
  endpointEphX = std::vector<uint8_t>();
  endpointEphPubKey = std::vector<uint8_t>();
  LOG(D, "Initialization Time: %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
}

/**
 * The function `authenticate` in the `HKAuthenticationContext` class processes authentication data and
 * returns the issuer and endpoint IDs along with the authentication flow type.
 * 
 * @param hkFlow The `hkFlow` parameter in the `authenticate` function is an integer that determines
 * the type of HomeKey flow to be used for authentication. It can have the following values defined in
 * the `homeKeyReader::KeyFlow` enum: kFlowFAST, kFlowSTANDARD and kFlowATTESTATION
 * 
 * @return A tuple containing the matching `issuerId` and `endpointId`, and the successful flow from
 * the enum `homeKeyReader::KeyFlow`.
 */
std::tuple<uint8_t *, uint8_t *, homeKeyReader::KeyFlow> HKAuthenticationContext::authenticate(homeKeyReader::KeyFlow hkFlow){
  auto startTime = std::chrono::high_resolution_clock::now();
  uint8_t prot_v_data[2] = {0x02, 0x0};

  std::vector<uint8_t> fastTlv(sizeof(prot_v_data) + readerEphPubKey.size() + transactionIdentifier.size() + readerIdentifier.size() + 8);
  size_t len = 0;
  utils::simple_tlv(0x5C, prot_v_data, sizeof(prot_v_data), fastTlv.data(), &len);

  utils::simple_tlv(0x87, readerEphPubKey.data(), readerEphPubKey.size(), fastTlv.data() + len, &len);

  utils::simple_tlv(0x4C, transactionIdentifier.data(), transactionIdentifier.size(), fastTlv.data() + len, &len);

  utils::simple_tlv(0x4D, readerIdentifier.data(), readerIdentifier.size(), fastTlv.data() + len, &len);
  std::vector<uint8_t> apdu{0x80, 0x80, 0x01, 0x01, (uint8_t)len};
  apdu.insert(apdu.begin() + 5, fastTlv.begin(), fastTlv.end());
  std::vector<uint8_t> response(90);
  uint8_t responseLength = 90;
  LOG(D, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), utils::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfcInDataExchange(apdu.data(), apdu.size(), response.data(), &responseLength);
  response.resize(responseLength);
  LOG(D, "Auth0 Response Length: %d, DATA: %s", responseLength, utils::bufToHexString(response.data(), responseLength).c_str());
  if (responseLength > 64 && response[0] == 0x86) {
    BerTlv Auth0Res;
    Auth0Res.SetTlv(response);
    Auth0Res.GetValue(int_to_hex(kEndpoint_Public_Key), &endpointEphPubKey);
    endpointEphX = std::move(get_x(endpointEphPubKey));
    homeKeyIssuer::issuer_t *foundIssuer = nullptr;
    homeKeyEndpoint::endpoint_t *foundEndpoint = nullptr;
    std::vector<uint8_t> persistentKey;
    homeKeyReader::KeyFlow flowUsed = homeKeyReader::kFlowFailed;
    if (hkFlow == homeKeyReader::kFlowFAST) {
      std::vector<uint8_t> encryptedMessage;
      Auth0Res.GetValue(int_to_hex(kAuth0_Cryptogram), &encryptedMessage);
      auto fastAuth = HKFastAuth(*readerData.reader_key_x, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest(encryptedMessage);
      if (std::get<1>(fastAuth) != nullptr && std::get<2>(fastAuth) != homeKeyReader::kFlowFailed)
      {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        flowUsed = std::get<2>(fastAuth);
        LOG(I, "FAST flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
        LOG(D, "Endpoint %s Authenticated via FAST Flow", utils::bufToHexString(foundEndpoint->endpointId, sizeof(foundEndpoint->endpointId), true).c_str());
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = HKStdAuth(nfcInDataExchange, *readerData.reader_private_key, readerEphPrivKey, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest();
      if(std::get<1>(stdAuth) != nullptr){
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if (std::get<4>(stdAuth) != homeKeyReader::kFlowFailed)
        {
          flowUsed = std::get<4>(stdAuth);
          LOG(I, "STANDARD Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", utils::bufToHexString(foundEndpoint->endpointId, sizeof(foundEndpoint->endpointId), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          memcpy(foundEndpoint->persistent_key, persistentKey.data(), 32);
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(foundEndpoint->persistent_key, 32).c_str());
        }
      }
      if(std::get<4>(stdAuth) == homeKeyReader::kFlowFailed || hkFlow == homeKeyReader::kFlowATTESTATION){
        auto attestation = HKAttestationAuth(readerData.issuers, std::get<2>(stdAuth), nfcInDataExchange).attest();
        if (std::get<1>(attestation) == homeKeyReader::kFlowATTESTATION) {
          homeKeyEndpoint::endpoint_t endpoint;
          foundIssuer = std::get<0>(std::get<0>(attestation));
          std::vector<uint8_t> devicePubKey = std::get<1>(std::get<0>(attestation));
          std::vector<uint8_t> deviceKeyX = std::get<2>(std::get<0>(attestation));
          std::move(deviceKeyX.begin(), deviceKeyX.end(), endpoint.endpoint_key_x);
          std::vector<uint8_t> eId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
          std::move(eId.begin(), eId.end(), endpoint.endpointId);
          std::move(devicePubKey.begin(), devicePubKey.end(), endpoint.publicKey);
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", utils::bufToHexString(endpoint.endpointId, sizeof(endpoint.endpointId), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          flowUsed = std::get<1>(attestation);
          memcpy(endpoint.persistent_key, persistentKey.data(), 32);
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(endpoint.persistent_key, 32).c_str());
          foundEndpoint = &*foundIssuer->endpoints.insert(foundIssuer->endpoints.end(),endpoint);
        }
      }
      if(flowUsed >= homeKeyReader::kFlowSTANDARD && persistentKey.size() > 0){
        json serializedData = readerData;
        auto msgpack = json::to_msgpack(serializedData);
        esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", msgpack.data(), msgpack.size());
        esp_err_t commit_nvs = nvs_commit(savedData);
        LOG(V, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
        LOG(V, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
      }
    }
    if(foundEndpoint != nullptr && flowUsed != homeKeyReader::kFlowFailed) {
      std::vector<uint8_t> cmdFlowStatus;
      if (flowUsed != homeKeyReader::kFlowATTESTATION)
      {
        cmdFlowStatus = commandFlow(homeKeyReader::kCmdFlowSuccess);
        LOG(D, "CONTROL FLOW RESPONSE: %s, Length: %d", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str(), cmdFlowStatus.size());
      }
      if (flowUsed == homeKeyReader::kFlowATTESTATION || cmdFlowStatus.data()[0] == 0x90)
      {
        return std::make_tuple(foundIssuer->issuerId, foundEndpoint->endpointId, flowUsed);
      } else {
        LOG(E, "Control Flow Response not 0x90!, %s", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str());
        return std::make_tuple(foundIssuer->issuerId, foundEndpoint->endpointId, homeKeyReader::kFlowFailed);
      }
    }
  }
  LOG(E, "Response not valid, something went wrong!");
  return std::make_tuple(static_cast<uint8_t*>(nullptr), static_cast<uint8_t*>(nullptr), homeKeyReader::kFlowFailed);
}

/**
 * The function `HKAuthenticationContext::commandFlow` sends the command flow status APDU command
 * and returns the response.
 * 
 * @param status The parameter "status" is of type "homeKeyReader::CommandFlowStatus"
 * 
 * @return a std::vector<uint8_t> object, which contains the received response
 */
std::vector<uint8_t> HKAuthenticationContext::commandFlow(homeKeyReader::CommandFlowStatus status)
{
  uint8_t apdu[4] = {0x80, 0x3c, status, status == homeKeyReader::kCmdFlowAttestation ? (uint8_t)0xa0 : (uint8_t)0x0};
  std::vector<uint8_t> cmdFlowRes(4);
  uint8_t cmdFlowResLen = cmdFlowRes.size();
  LOG(D, "APDU: %s, Length: %d", utils::bufToHexString(apdu, sizeof(apdu)).c_str(), sizeof(apdu));
  nfcInDataExchange(apdu, sizeof(apdu), cmdFlowRes.data(), &cmdFlowResLen);
  return cmdFlowRes;
}