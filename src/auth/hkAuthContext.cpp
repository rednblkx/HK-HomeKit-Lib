#include <hkAuthContext.h>
#include <pb_encode.h>

/**
 * The HKAuthenticationContext constructor generates an ephemeral key for the reader and initializes
 * core variables
 *
 * @param nfcInDataExchange The `nfcInDataExchange` parameter is a function pointer that points to a
 * function responsible for exchanging data with an NFC device. It takes input data, its length, and
 * returns a response along with the response length.
 * @param readerData The `readerData` parameter is a reference to an object of type
 * `HomeKeyData_ReaderData`.
 * @param savedData The `savedData` parameter in the `HKAuthenticationContext` constructor is of type
 * `nvs_handle`, which is a handle to a Non-Volatile Storage (NVS) namespace in ESP-IDF
 * (Espressif IoT Development Framework). This handle is used to access and manipulate data stored.
 */
HKAuthenticationContext::HKAuthenticationContext(PN532 &nfc, HomeKeyData_ReaderData &readerData, nvs_handle &savedData) : readerData(readerData), savedData(savedData), nfc(nfc)
{
  // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = generateEphemeralKey();
  readerEphPrivKey = std::move(std::get<0>(readerEphKey));
  readerEphPubKey = std::move(std::get<1>(readerEphKey));
  transactionIdentifier.resize(16);
  transactionIdentifier.reserve(16);
  esp_fill_random(transactionIdentifier.data(), 16);
  readerIdentifier.reserve(sizeof(readerData.reader_group_id) + sizeof(readerData.reader_id));
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_group_id, readerData.reader_group_id + sizeof(readerData.reader_group_id));
  readerIdentifier.insert(readerIdentifier.end(), readerData.reader_id, readerData.reader_id + sizeof(readerData.reader_id));
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
 * the `KeyFlow` enum: kFlowFAST, kFlowSTANDARD and kFlowATTESTATION
 * 
 * @return A tuple containing the matching `issuer_id` and `ep_id`, and the successful flow from
 * the enum `KeyFlow`.
 */
std::tuple<uint8_t *, uint8_t *, KeyFlow> HKAuthenticationContext::authenticate(KeyFlow hkFlow){
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
  std::vector<uint8_t> response(91);
  uint16_t responseLength = 91;
  LOG(D, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), utils::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfc.inDataExchange(apdu.data(), apdu.size(), response.data(), &responseLength);
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, response.data(), responseLength, ESP_LOG_VERBOSE);
  response.resize(responseLength);
  LOG(D, "Auth0 Response Length: %d, DATA: %s", responseLength, utils::bufToHexString(response.data(), responseLength).c_str());
  if (responseLength > 64 && response[0] == 0x86) {
    BerTlv Auth0Res;
    Auth0Res.SetTlv(response);
    Auth0Res.GetValue(int_to_hex(kEndpoint_Public_Key), &endpointEphPubKey);
    endpointEphX = std::move(get_x(endpointEphPubKey));
    HomeKeyData_KeyIssuer *foundIssuer = nullptr;
    HomeKeyData_Endpoint *foundEndpoint = nullptr;
    std::vector<uint8_t> persistentKey;
    KeyFlow flowUsed = kFlowFailed;
    if (hkFlow == kFlowFAST) {
      std::vector<uint8_t> encryptedMessage;
      Auth0Res.GetValue(int_to_hex(kAuth0_Cryptogram), &encryptedMessage);
      auto fastAuth = HKFastAuth(*readerData.reader_pk_x, readerData.issuers, readerData.issuers_count, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest(encryptedMessage);
      if (std::get<1>(fastAuth) != nullptr && std::get<2>(fastAuth) != kFlowFailed)
      {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        flowUsed = std::get<2>(fastAuth);
        LOG(D, "Endpoint %s Authenticated via FAST Flow", utils::bufToHexString(foundEndpoint->ep_id, sizeof(foundEndpoint->ep_id), true).c_str());
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = HKStdAuth(nfc, *readerData.reader_sk, readerEphPrivKey, readerData.issuers, readerData.issuers_count, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest();
      if(std::get<1>(stdAuth) != nullptr){
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if ((flowUsed = std::get<4>(stdAuth)) != kFlowFailed)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", utils::bufToHexString(foundEndpoint->ep_id, sizeof(foundEndpoint->ep_id), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          memcpy(foundEndpoint->ep_persistent_key, persistentKey.data(), 32);
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(foundEndpoint->ep_persistent_key, 32).c_str());
        }
      }
      if (std::get<4>(stdAuth) == kFlowFailed || hkFlow == kFlowATTESTATION) {
        auto attestation = HKAttestationAuth(readerData.issuers, readerData.issuers_count, std::get<2>(stdAuth), nfc).attest();
        if ((flowUsed = std::get<2>(attestation)) == kFlowATTESTATION) {
          HomeKeyData_Endpoint endpoint;
          foundIssuer = std::get<0>(attestation);
          std::vector<uint8_t> devicePubKey = std::get<1>(attestation);
          std::vector<uint8_t> deviceKeyX = get_x(std::get<1>(attestation));
          std::move(deviceKeyX.begin(), deviceKeyX.end(), endpoint.ep_pk_x);
          std::vector<uint8_t> eId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
          std::move(eId.begin(), eId.end(), endpoint.ep_id);
          std::move(devicePubKey.begin(), devicePubKey.end(), endpoint.ep_pk);
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", utils::bufToHexString(endpoint.ep_id, sizeof(endpoint.ep_id), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          memcpy(endpoint.ep_persistent_key, persistentKey.data(), 32);
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(endpoint.ep_persistent_key, 32).c_str());
          foundIssuer->endpoints[foundIssuer->endpoints_count] = endpoint;
          foundIssuer->endpoints_count++;
          foundEndpoint = &foundIssuer->endpoints[foundIssuer->endpoints_count];
        }
      }
      if(flowUsed >= kFlowSTANDARD && persistentKey.size() > 0){
        uint8_t* buffer = (uint8_t*)malloc(HomeKeyData_ReaderData_size);
        pb_ostream_t ostream = pb_ostream_from_buffer(buffer, HomeKeyData_ReaderData_size);
        bool encodeStatus = pb_encode(&ostream, &HomeKeyData_ReaderData_msg, &readerData);
        LOG(I, "PB ENCODE STATUS: %d", encodeStatus);
        LOG(I, "PB BYTES WRITTEN: %d", ostream.bytes_written);
        esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", buffer, ostream.bytes_written);
        esp_err_t commit_nvs = nvs_commit(savedData);
        LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
        LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
        free(buffer);
      }
    }
    if(foundEndpoint != nullptr && flowUsed != kFlowFailed) {
      std::vector<uint8_t> cmdFlowStatus;
      if (flowUsed < kFlowATTESTATION)
      {
        cmdFlowStatus = commandFlow(kCmdFlowSuccess);
        LOG(D, "CONTROL FLOW RESPONSE: %s, Length: %d", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str(), cmdFlowStatus.size());
      }
      if (flowUsed == kFlowATTESTATION || cmdFlowStatus.data()[0] == 0x90)
      {
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->ep_id, flowUsed);
      } else {
        LOG(E, "Control Flow Response not 0x90!, %s", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->ep_id, kFlowFailed);
      }
    }
  }
  LOG(E, "Response not valid, something went wrong!");
  return std::make_tuple(static_cast<uint8_t*>(nullptr), static_cast<uint8_t*>(nullptr), kFlowFailed);
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
  uint8_t apdu[4] = {0x80, 0x3c, status, status == kCmdFlowAttestation ? (uint8_t)0xa0 : (uint8_t)0x0};
  std::vector<uint8_t> cmdFlowRes(4);
  uint16_t cmdFlowResLen = cmdFlowRes.size();
  LOG(D, "APDU: %s, Length: %d", utils::bufToHexString(apdu, sizeof(apdu)).c_str(), sizeof(apdu));
  nfc.inDataExchange(apdu, sizeof(apdu), cmdFlowRes.data(), &cmdFlowResLen);
  return cmdFlowRes;
}