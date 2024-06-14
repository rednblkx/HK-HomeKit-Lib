#include <hkAuthContext.h>

/**
 * The HKAuthenticationContext constructor generates an ephemeral key for the reader and initializes
 * core variables
 *
 * @param nfcInDataExchange The `nfcInDataExchange` parameter is a function pointer that points to a
 * function responsible for exchanging data with an NFC device. It takes input data, its length, and
 * returns a response along with the response length.
 * @param readerData The `readerData` parameter is a reference to an object of type
 * `readerData_t`.
 * @param savedData The `savedData` parameter in the `HKAuthenticationContext` constructor is of type
 * `nvs_handle`, which is a handle to a Non-Volatile Storage (NVS) namespace in ESP-IDF
 * (Espressif IoT Development Framework). This handle is used to access and manipulate data stored.
 */
HKAuthenticationContext::HKAuthenticationContext(std::function<bool(uint8_t*, uint8_t, uint8_t*, uint16_t*, bool)> &nfc, readerData_t &readerData, nvs_handle &savedData) : readerData(readerData), savedData(savedData), nfc(nfc)
{
  // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = generateEphemeralKey();
  readerEphPrivKey = std::move(std::get<0>(readerEphKey));
  readerEphPubKey = std::move(std::get<1>(readerEphKey));
  transactionIdentifier.resize(16);
  esp_fill_random(transactionIdentifier.data(), 16);
  readerIdentifier.reserve(readerData.reader_gid.size() + readerData.reader_id.size());
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_gid.begin(), readerData.reader_gid.end());
  readerIdentifier.insert(readerIdentifier.end(), readerData.reader_id.begin(), readerData.reader_id.end());
  readerEphX = std::move(get_x(readerEphPubKey));
  auto stopTime = std::chrono::high_resolution_clock::now();
  endpointEphX = std::vector<uint8_t>();
  endpointEphPubKey = std::vector<uint8_t>();
  LOG(I, "Initialization Time: %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
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
  utils::simple_tlv(0x5C, prot_v_data, sizeof(prot_v_data), fastTlv.data(), &len);

  utils::simple_tlv(0x87, readerEphPubKey.data(), readerEphPubKey.size(), fastTlv.data() + len, &len);

  utils::simple_tlv(0x4C, transactionIdentifier.data(), transactionIdentifier.size(), fastTlv.data() + len, &len);

  utils::simple_tlv(0x4D, readerIdentifier.data(), readerIdentifier.size(), fastTlv.data() + len, &len);
  std::vector<uint8_t> apdu{0x80, 0x80, 0x01, 0x01, (uint8_t)len};
  apdu.insert(apdu.begin() + 5, fastTlv.begin(), fastTlv.end());
  std::vector<uint8_t> response(91);
  uint16_t responseLength = 91;
  LOG(D, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), utils::bufToHexString(apdu.data(), apdu.size()).c_str());
  nfc(apdu.data(), apdu.size(), response.data(), &responseLength, false);
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, response.data(), responseLength, ESP_LOG_VERBOSE);
  response.resize(responseLength);
  LOG(D, "Auth0 Response Length: %d, DATA: %s", responseLength, utils::bufToHexString(response.data(), responseLength).c_str());
  if (responseLength > 64 && response[0] == 0x86) {
    TLV Auth0Res(NULL, 0);
    Auth0Res.unpack(response.data(), response.size());
    TLV_it pubkey = Auth0Res.find(kEndpoint_Public_Key);
    endpointEphPubKey = std::vector<uint8_t>{ (*pubkey).val.get(), (*pubkey).val.get() + (*pubkey).len };
    endpointEphX = std::move(get_x(endpointEphPubKey));
    hkIssuer_t *foundIssuer = nullptr;
    hkEndpoint_t *foundEndpoint = nullptr;
    std::vector<uint8_t> persistentKey;
    KeyFlow flowUsed = kFlowFailed;
    if (hkFlow == kFlowFAST) {
      TLV_it crypt = Auth0Res.find(kAuth0_Cryptogram);
      std::vector<uint8_t> encryptedMessage{(*crypt).val.get(), (*crypt).val.get() + (*crypt).len};
      auto fastAuth = HKFastAuth(readerData.reader_pk_x, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest(encryptedMessage);
      if (std::get<1>(fastAuth) != nullptr && std::get<2>(fastAuth) != kFlowFailed)
      {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        flowUsed = std::get<2>(fastAuth);
        LOG(D, "Endpoint %s Authenticated via FAST Flow", utils::bufToHexString(foundEndpoint->endpoint_id.data(), foundEndpoint->endpoint_id.size(), true).c_str());
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = HKStdAuth(nfc, readerData.reader_sk, readerEphPrivKey, readerData.issuers, readerEphX, endpointEphPubKey, endpointEphX, transactionIdentifier, readerIdentifier).attest();
      if(std::get<1>(stdAuth) != nullptr){
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if ((flowUsed = std::get<4>(stdAuth)) != kFlowFailed)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", utils::bufToHexString(foundEndpoint->endpoint_id.data(), foundEndpoint->endpoint_id.size(), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          foundEndpoint->endpoint_prst_k = persistentKey;
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(foundEndpoint->endpoint_prst_k.data(), foundEndpoint->endpoint_prst_k.size()).c_str());
        }
      }
      if (std::get<4>(stdAuth) == kFlowFailed || hkFlow == kFlowATTESTATION) {
        auto attestation = HKAttestationAuth(readerData.issuers, std::get<2>(stdAuth), nfc).attest();
        if ((flowUsed = std::get<2>(attestation)) == kFlowATTESTATION) {
          hkEndpoint_t endpoint;
          foundIssuer = std::get<0>(attestation);
          std::vector<uint8_t> devicePubKey = std::get<1>(attestation);
          std::vector<uint8_t> deviceKeyX = get_x(std::get<1>(attestation));
          endpoint.endpoint_pk_x = deviceKeyX;
          std::vector<uint8_t> eId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
          endpoint.endpoint_id = std::vector<uint8_t>{eId.begin(), eId.begin() + 6};
          endpoint.endpoint_pk = devicePubKey;
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", utils::bufToHexString(endpoint.endpoint_id.data(), endpoint.endpoint_id.size(), true).c_str());
          persistentKey = std::get<3>(stdAuth);
          endpoint.endpoint_prst_k = persistentKey;
          LOG(D, "New Persistent Key: %s", utils::bufToHexString(endpoint.endpoint_prst_k.data(), endpoint.endpoint_prst_k.size()).c_str());
          foundEndpoint = &(*foundIssuer->endpoints.emplace(foundIssuer->endpoints.end(),endpoint));
        }
      }
      if(flowUsed >= kFlowSTANDARD && persistentKey.size() > 0){
        std::vector<uint8_t> cborBuf;
        jsoncons::cbor::encode_cbor(readerData, cborBuf);
        esp_err_t set_nvs = nvs_set_blob(savedData, "READERDATA", cborBuf.data(), cborBuf.size());
        esp_err_t commit_nvs = nvs_commit(savedData);
        LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
        LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
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
        LOG(I, "Endpoint authenticated, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, flowUsed);
      } else {
        LOG(E, "Control Flow Response not 0x90!, %s", utils::bufToHexString(cmdFlowStatus.data(), cmdFlowStatus.size()).c_str());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, kFlowFailed);
      }
    }
  }
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
  uint8_t apdu[4] = {0x80, 0x3c, status, status == kCmdFlowAttestation ? (uint8_t)0xa0 : (uint8_t)0x0};
  std::vector<uint8_t> cmdFlowRes(4);
  uint16_t cmdFlowResLen = cmdFlowRes.size();
  LOG(D, "APDU: %s, Length: %d", utils::bufToHexString(apdu, sizeof(apdu)).c_str(), sizeof(apdu));
  nfc(apdu, sizeof(apdu), cmdFlowRes.data(), &cmdFlowResLen, false);
  return cmdFlowRes;
}