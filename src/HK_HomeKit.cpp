#include <HK_HomeKit.h>

HK_HomeKit::HK_HomeKit(std::vector<uint8_t> tlvData, homeKeyReader::readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey) : readerData(readerData), nvsHandle(nvsHandle), nvsKey(nvsKey) {
  tlv.SetTlv(tlvData);
}

std::vector<uint8_t> HK_HomeKit::processResult() {
  std::vector<uint8_t> operation;
  std::vector<uint8_t> RKR;
  std::vector<uint8_t> DCR;
  tlv.GetValue(int_to_hex(kReader_Operation), &operation);
  switch (*operation.data()) {
  case kReader_Operation_Read:
    if (tlv.GetValue(int_to_hex(kReader_Reader_Key_Request), &RKR) == TLV_OK) {
      LOG(I, "GET READER KEY REQUEST");
      if (memcmp(readerData.reader_private_key, std::vector<uint8_t>(32, 0).data(), 32)) {
        size_t out_len = 0;
        BerTlv subTlv;
        subTlv.Add(int_to_hex(kReader_Res_Key_Identifier), std::vector<uint8_t>{readerData.reader_identifier, readerData.reader_identifier + sizeof(readerData.reader_identifier)});
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", subTlv.GetTlv().size(), subTlv.GetTlvAsHexString().c_str());
        BerTlv resTlv;
        resTlv.Add(int_to_hex(kReader_Res_Reader_Key_Response), subTlv.GetTlv());
        LOG(D, "TLV LENGTH: %d, DATA: %s", resTlv.GetTlv().size(), resTlv.GetTlvAsHexString().c_str());
        mbedtls_base64_encode(NULL, 0, &out_len, resTlv.GetTlv().data(), resTlv.GetTlv().size());
        std::vector<uint8_t> resB64(out_len + 1);
        int ret = mbedtls_base64_encode(resB64.data(), resB64.size(), &out_len, resTlv.GetTlv().data(), resTlv.GetTlv().size());
        resB64[out_len] = '\0';
        LOG(D, "B64 ENC STATUS: %d", ret);
        LOG(D, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64.data());
        return resB64;
      }
    }
    break;

  case kReader_Operation_Write:
    if (tlv.GetValue(int_to_hex(kReader_Reader_Key_Request), &RKR) == TLV_OK) {
      LOG(I, "SET READER KEY REQUEST");
      int ret = set_reader_key(RKR);
      if (ret == 0) {
        LOG(I, "READER KEY SAVED TO NVS, COMPOSING RESPONSE");
        size_t out_len = 0;
        BerTlv rkResSubTlv;
        rkResSubTlv.Add(int_to_hex(kReader_Res_Status), 0);
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", rkResSubTlv.GetTlv().size(), rkResSubTlv.GetTlvAsHexString().c_str());
        BerTlv rkResTlv;
        rkResTlv.Add(int_to_hex(kReader_Res_Reader_Key_Response), rkResSubTlv.GetTlv());
        LOG(D, "TLV LENGTH: %d, DATA: %s", rkResTlv.GetTlv().size(), rkResTlv.GetTlvAsHexString().c_str());
        mbedtls_base64_encode(NULL, 0, &out_len, rkResTlv.GetTlv().data(), rkResTlv.GetTlv().size());
        std::vector<uint8_t> resB64(out_len + 1);
        int ret = mbedtls_base64_encode(resB64.data(), resB64.size(), &out_len, rkResTlv.GetTlv().data(), rkResTlv.GetTlv().size());
        resB64[out_len] = '\0';
        LOG(D, "B64 ENC STATUS: %d", ret);
        LOG(I, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64.data());
        return resB64;
      }
    }
    else if (tlv.GetValue(int_to_hex(kReader_Device_Credential_Request), &DCR) == TLV_OK) {
      LOG(D, "PROVISION DEVICE CREDENTIAL REQUEST");
      std::tuple<uint8_t*, int> state = provision_device_cred(DCR);
      if (std::get<1>(state) != 99 && std::get<0>(state) != NULL) {
        size_t out_len = 0;
        BerTlv dcrResSubTlv;
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Issuer_Key_Identifier), std::vector<uint8_t>{std::get<0>(state), std::get<0>(state) + 8});
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Status), int_to_hex(std::get<1>(state)));
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", dcrResSubTlv.GetTlv().size(), dcrResSubTlv.GetTlvAsHexString().c_str());
        BerTlv dcrResTlv;
        dcrResTlv.Add(int_to_hex(kDevice_Credential_Response), dcrResSubTlv.GetTlv());
        LOG(D, "TLV LENGTH: %d, DATA: %s", dcrResTlv.GetTlv().size(), dcrResTlv.GetTlvAsHexString().c_str());
        mbedtls_base64_encode(NULL, 0, &out_len, dcrResTlv.GetTlv().data(), dcrResTlv.GetTlv().size());
        std::vector<uint8_t> resB64(out_len + 1);
        int ret = mbedtls_base64_encode(resB64.data(), resB64.size(), &out_len, dcrResTlv.GetTlv().data(), dcrResTlv.GetTlv().size());
        resB64[out_len] = '\0';
        LOG(D, "B64 ENC STATUS: %d", ret);
        LOG(I, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64.data());
        return resB64;
      }
    }
    break;
  case kReader_Operation_Remove:
    if (tlv.GetValue(int_to_hex(kReader_Reader_Key_Request), &RKR) == TLV_OK) {
      LOG(I, "REMOVE READER KEY REQUEST");
      std::fill(readerData.reader_identifier, readerData.reader_identifier + 8, 0);
      std::fill(readerData.reader_private_key, readerData.reader_private_key + 32, 0);
      save_to_nvs();
      const char* res = "BwMCAQA=";
      size_t resLen = 9;
      LOG(I, "RESPONSE LENGTH: %d, DATA: %s", resLen, res);
      return std::vector<uint8_t>(res, res+sizeof(res));
    }
    break;
  default:
    break;
  }
  return std::vector<uint8_t>();
}

std::tuple<uint8_t*, int> HK_HomeKit::provision_device_cred(std::vector<uint8_t> buf) {
  LOG(D, "DCReq Buffer length: %d, data: %s", buf.size(), utils::bufToHexString(buf.data(), buf.size()).c_str());
  BerTlv dcrTlv;
  dcrTlv.SetTlv(buf);
  homeKeyIssuer::issuer_t* foundIssuer = nullptr;
  std::vector<uint8_t> issuerIdentifier;
  if (dcrTlv.GetValue(int_to_hex(kDevice_Req_Issuer_Key_Identifier), &issuerIdentifier) == TLV_OK) {
    for (auto& issuer : readerData.issuers) {
      if (!memcmp(issuer.issuerId, issuerIdentifier.data(), 8)) {
        LOG(D, "Found issuer - ID: %s", utils::bufToHexString(issuer.issuerId, 8).c_str());
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      homeKeyEndpoint::endpoint_t* foundEndpoint = 0;
      std::vector<uint8_t> devicePubKey;
      dcrTlv.GetValue(int_to_hex(kDevice_Req_Public_Key), &devicePubKey);
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> endpointId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (!memcmp(endpoint.endpointId, endpointId.data(), 6)) {
          LOG(D, "Found endpoint - ID: %s", utils::bufToHexString(endpoint.endpointId, 6).c_str());
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == 0) {
        LOG(D, "Adding new endpoint - ID: %s , PublicKey: %s", utils::bufToHexString(endpointId.data(), 6).c_str(), utils::bufToHexString(devicePubKey.data(), devicePubKey.size()).c_str());
        homeKeyEndpoint::endpoint_t endpoint;
        endpointEnrollment::enrollment_t hap;
        hap.unixTime = std::time(nullptr);
        uint8_t encoded[128];
        size_t olen = 0;
        mbedtls_base64_encode(encoded, 128, &olen, buf.data(), buf.size());
        hap.payload.insert(hap.payload.begin(), encoded, encoded + olen);
        std::vector<uint8_t> x_coordinate = get_x(devicePubKey.data(), devicePubKey.size());
        std::vector<uint8_t> keyType;
        dcrTlv.GetValue(int_to_hex(kDevice_Req_Key_Type), &keyType);
        endpoint.counter = 0;
        endpoint.key_type = *keyType.data();
        endpoint.last_used_at = 0;
        endpoint.enrollments.hap = hap;
        std::fill(endpoint.persistent_key, endpoint.persistent_key + 32, 0);
        memcpy(endpoint.endpointId, endpointId.data(), 6);
        memcpy(endpoint.publicKey, devicePubKey.data(), devicePubKey.size());
        memcpy(endpoint.endpoint_key_x, x_coordinate.data(), x_coordinate.size());
        foundIssuer->endpoints.emplace_back(endpoint);
        save_to_nvs();
        return std::make_tuple(foundIssuer->issuerId, homeKeyReader::SUCCESS);
      }
      else {
        LOG(D, "Endpoint already exists - ID: %s", utils::bufToHexString(foundEndpoint->endpointId, 6).c_str());
        save_to_nvs();
        return std::make_tuple(issuerIdentifier.data(), homeKeyReader::DUPLICATE);
      }
    }
    else {
      LOG(D, "Issuer does not exist - ID: %s", utils::bufToHexString(issuerIdentifier.data(), 8).c_str());
      save_to_nvs();
      return std::make_tuple(issuerIdentifier.data(), homeKeyReader::DOES_NOT_EXIST);
    }
  }
  return std::make_tuple(readerData.reader_identifier, homeKeyReader::DOES_NOT_EXIST);
}

int HK_HomeKit::set_reader_key(std::vector<uint8_t> buf) {
  LOG(D, "Setting reader key: %s", utils::bufToHexString(buf.data(), buf.size()).c_str());
  BerTlv rkrTLv;
  std::vector<uint8_t> readerKey;
  rkrTLv.GetValue(int_to_hex(kReader_Req_Reader_Private_Key), &readerKey);
  std::vector<uint8_t> uniqueIdentifier;
  rkrTLv.GetValue(int_to_hex(kReader_Req_Identifier), &uniqueIdentifier);
  LOG(D, "Reader Key: %s", utils::bufToHexString(readerKey.data(), readerKey.size()).c_str());
  LOG(D, "UniqueIdentifier: %s", utils::bufToHexString(uniqueIdentifier.data(), uniqueIdentifier.size()).c_str());
  std::vector<uint8_t> pubKey = getPublicKey(readerKey.data(), readerKey.size());
  LOG(D, "Got reader public key: %s", utils::bufToHexString(pubKey.data(), pubKey.size()).c_str());
  std::vector<uint8_t> x_coordinate = get_x(pubKey.data(), pubKey.size());
  LOG(D, "Got X coordinate: %s", utils::bufToHexString(x_coordinate.data(), x_coordinate.size()).c_str());
  memcpy(readerData.reader_key_x, x_coordinate.data(), x_coordinate.size());
  memcpy(readerData.reader_public_key, pubKey.data(), pubKey.size());
  memcpy(readerData.reader_private_key, readerKey.data(), readerKey.size());
  memcpy(readerData.identifier, uniqueIdentifier.data(), uniqueIdentifier.size());
  std::vector<uint8_t> readeridentifier = utils::getHashIdentifier(readerData.reader_private_key, sizeof(readerData.reader_private_key), true);
  LOG(D, "Reader GroupIdentifier: %s", utils::bufToHexString(readeridentifier.data(), 8).c_str());
  memcpy(readerData.reader_identifier, readeridentifier.data(), 8);
  bool nvs = save_to_nvs();
  if (nvs) {
    return 0;
  }
  else
    return 1;
}

bool HK_HomeKit::save_to_nvs() {
  json serializedData = readerData;
  auto msgpack = json::to_msgpack(serializedData);
  esp_err_t set_nvs = nvs_set_blob(nvsHandle, nvsKey, msgpack.data(), msgpack.size());
  esp_err_t commit_nvs = nvs_commit(nvsHandle);
  ESP_LOGV("save_to_nvs", "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  ESP_LOGV("save_to_nvs", "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  return !set_nvs && !commit_nvs;
}