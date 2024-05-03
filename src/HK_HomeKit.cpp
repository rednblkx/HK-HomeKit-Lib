#include <HK_HomeKit.h>

HK_HomeKit::HK_HomeKit(HomeKeyData_ReaderData& readerData, nvs_handle& nvsHandle, const char* nvsKey) : readerData(readerData), nvsHandle(nvsHandle), nvsKey(nvsKey) {
  esp_log_level_set(TAG, ESP_LOG_DEBUG);
}

std::vector<uint8_t> HK_HomeKit::processResult(std::vector<uint8_t> tlvData) {
  TLV8_it operation;
  TLV8_it RKR;
  TLV8_it DCR;
  TLV8 rxTlv(NULL, 0);
  rxTlv.unpack(tlvData.data(), tlvData.size());
  operation = rxTlv.find(kReader_Operation);
  RKR = rxTlv.find(kReader_Reader_Key_Request);
  DCR = rxTlv.find(kReader_Device_Credential_Request);
  if (rxTlv.len(operation) > 0) {
  LOG(I, "TLV OPERATION: %d", (*(*operation).val.get()));
    if ((*(*operation).val.get()) == kReader_Operation_Read)
      if ((*RKR).tag == kReader_Reader_Key_Request) {
        LOG(I, "GET READER KEY REQUEST");
        if (memcmp(readerData.reader_sk, std::vector<uint8_t>(32, 0).data(), 32)) {
          // size_t out_len = 0;
          TLV8 getResSub(NULL, 0);
          // BerTlv subTlv;
          getResSub.add(kReader_Res_Key_Identifier, sizeof(readerData.reader_group_id), readerData.reader_group_id);
          uint8_t subTlv[getResSub.pack_size()];
          // subTlv.Add(int_to_hex(kReader_Res_Key_Identifier), std::vector<uint8_t>{readerData.reader_group_id, readerData.reader_group_id + sizeof(readerData.reader_group_id)});
          getResSub.pack(subTlv);
          LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", sizeof(subTlv), utils::bufToHexString(subTlv, sizeof(subTlv)).c_str());
          TLV8 getResTlv(NULL, 0);
          // BerTlv resTlv;
          getResTlv.add(kReader_Res_Reader_Key_Response, sizeof(subTlv), subTlv);
          uint8_t tlvRes[getResTlv.pack_size()];
          getResTlv.pack(tlvRes);
          LOG(D, "TLV LENGTH: %d, DATA: %s", sizeof(tlvRes), utils::bufToHexString(tlvRes, sizeof(tlvRes)).c_str());
          // mbedtls_base64_encode(NULL, 0, &out_len, resTlv.GetTlv().data(), resTlv.GetTlv().size());
          // std::vector<uint8_t> resB64(out_len + 1);
          // int ret = mbedtls_base64_encode(resB64.data(), resB64.size(), &out_len, resTlv.GetTlv().data(), resTlv.GetTlv().size());
          // resB64[out_len] = '\0';
          // LOG(D, "B64 ENC STATUS: %d", ret);
          // LOG(D, "RESPONSE LENGTH: %d, DATA: %s", out_len, resB64.data());
          esp_log_buffer_hex_internal(TAG, tlvRes, sizeof(tlvRes), ESP_LOG_INFO);
          return std::vector<uint8_t>(tlvRes, tlvRes + sizeof(tlvRes));
        }
        // else {
        uint8_t res[] = { 0x01, 0x01, 0x01, 0x7, 0x0 };
        return std::vector<uint8_t>(res, res + sizeof(res));
      // }
      }
  }
  if ((*(*operation).val.get()) == kReader_Operation_Write) {
    if (rxTlv.len(RKR) > 0) {
      LOG(I, "TLV RKR: %d", (*(*RKR).val.get()));
      LOG(I, "SET READER KEY REQUEST");
      int ret = set_reader_key(std::vector<uint8_t>((*RKR).val.get(), (*RKR).val.get() + (*RKR).len));
      if (ret == 0) {
        LOG(I, "READER KEY SAVED TO NVS, COMPOSING RESPONSE");
        // size_t out_len = 0;
        TLV8 rkResSub(NULL, 0);
        rkResSub.add(kReader_Res_Status, 1, {});
        uint8_t rkSubTlv[rkResSub.pack_size()];
        rkResSub.pack(rkSubTlv);
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", sizeof(rkSubTlv), utils::bufToHexString(rkSubTlv, sizeof(rkSubTlv)).c_str());
        TLV8 rkResTlv(NULL, 0);
        rkResTlv.add(kReader_Res_Reader_Key_Response, sizeof(rkSubTlv), rkSubTlv);
        uint8_t rkRes[rkResTlv.pack_size()];
        rkResTlv.pack(rkRes);
        esp_log_buffer_hex_internal(TAG, rkRes, sizeof(rkRes), ESP_LOG_INFO);
        return std::vector<uint8_t>(rkRes, rkRes + sizeof(rkRes));
      }
    }
    else if (rxTlv.len(DCR) > 0) {
      LOG(I, "TLV DCR: %d", (*(*DCR).val.get()));
      LOG(D, "PROVISION DEVICE CREDENTIAL REQUEST");
      std::tuple<uint8_t*, int> state = provision_device_cred(std::vector<uint8_t>((*DCR).val.get(), (*DCR).val.get() + (*DCR).len));
      if (std::get<1>(state) != 99 && std::get<0>(state) != NULL) {
        size_t out_len = 0;
        BerTlv dcrResSubTlv;
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Issuer_Key_Identifier), std::vector<uint8_t>{std::get<0>(state), std::get<0>(state) + 8});
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Status), int_to_hex(std::get<1>(state)));
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", dcrResSubTlv.GetTlv().size(), dcrResSubTlv.GetTlvAsHexString().c_str());
        BerTlv dcrResTlv;
        dcrResTlv.Add(int_to_hex(kDevice_Credential_Response), dcrResSubTlv.GetTlv());
        LOG(D, "TLV LENGTH: %d, DATA: %s", dcrResTlv.GetTlv().size(), dcrResTlv.GetTlvAsHexString().c_str());
        esp_log_buffer_hex_internal(TAG, dcrResTlv.GetTlv().data(), dcrResTlv.GetTlv().size(), ESP_LOG_INFO);
        return std::move(dcrResTlv.GetTlv());
      }
    }
  }
  if ((*(*operation).val.get()) == kReader_Operation_Remove)
    if (rxTlv.len(RKR) > 0) {
      LOG(I, "REMOVE READER KEY REQUEST");
      std::fill(readerData.reader_group_id, readerData.reader_group_id + 8, 0);
      std::fill(readerData.reader_sk, readerData.reader_sk + 32, 0);
      save_to_nvs();
      // const char* res = "BwMCAQA=";
      uint8_t res[] = { 0x7, 0x3, 0x2, 0x1, 0x0 };
      // size_t resLen = 9;
      // LOG(I, "RESPONSE LENGTH: %d, DATA: %s", resLen, res);
      esp_log_buffer_hex_internal(TAG, res, sizeof(res), ESP_LOG_INFO);
      return std::vector<uint8_t>(res, res + sizeof(res));
    }
  return std::vector<uint8_t>();
}

std::tuple<uint8_t*, int> HK_HomeKit::provision_device_cred(std::vector<uint8_t> buf) {
  LOG(D, "DCReq Buffer length: %d, data: %s", buf.size(), utils::bufToHexString(buf.data(), buf.size()).c_str());
  BerTlv dcrTlv;
  dcrTlv.SetTlv(buf);
  HomeKeyData_KeyIssuer* foundIssuer = nullptr;
  std::vector<uint8_t> issuerIdentifier;
  if (dcrTlv.GetValue(int_to_hex(kDevice_Req_Issuer_Key_Identifier), &issuerIdentifier) == TLV_OK) {
    for (auto& issuer : readerData.issuers) {
      if (!memcmp(issuer.issuer_id, issuerIdentifier.data(), 8)) {
        LOG(D, "Found issuer - ID: %s", utils::bufToHexString(issuer.issuer_id, 8).c_str());
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      HomeKeyData_Endpoint* foundEndpoint = 0;
      std::vector<uint8_t> devicePubKey;
      dcrTlv.GetValue(int_to_hex(kDevice_Req_Public_Key), &devicePubKey);
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> endpointId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (!memcmp(endpoint.ep_id, endpointId.data(), 6)) {
          LOG(D, "Found endpoint - ID: %s", utils::bufToHexString(endpoint.ep_id, 6).c_str());
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == 0) {
        LOG(D, "Adding new endpoint - ID: %s , PublicKey: %s", utils::bufToHexString(endpointId.data(), 6).c_str(), utils::bufToHexString(devicePubKey.data(), devicePubKey.size()).c_str());
        HomeKeyData_Endpoint endpoint;
        // endpointEnrollment::enrollment_t hap;
        // hap.unixTime = std::time(nullptr);
        // uint8_t encoded[128];
        // size_t olen = 0;
        // mbedtls_base64_encode(encoded, 128, &olen, buf.data(), buf.size());
        // hap.payload.insert(hap.payload.begin(), encoded, encoded + olen);
        std::vector<uint8_t> x_coordinate = get_x(devicePubKey.data(), devicePubKey.size());
        std::vector<uint8_t> keyType;
        dcrTlv.GetValue(int_to_hex(kDevice_Req_Key_Type), &keyType);
        endpoint.counter = 0;
        endpoint.key_type = *keyType.data();
        endpoint.last_used = 0;
        // endpoint.enrollments.hap = hap;
        std::fill(endpoint.ep_persistent_key, endpoint.ep_persistent_key + 32, 0);
        memcpy(endpoint.ep_id, endpointId.data(), 6);
        memcpy(endpoint.ep_pk, devicePubKey.data(), devicePubKey.size());
        memcpy(endpoint.ep_pk_x, x_coordinate.data(), x_coordinate.size());
        foundIssuer->endpoints[foundIssuer->endpoints_count] = endpoint;
        foundIssuer->endpoints_count++;
        // foundIssuer->endpoints.emplace_back(endpoint);
        save_to_nvs();
        return std::make_tuple(foundIssuer->issuer_id, SUCCESS);
      }
      else {
        LOG(D, "Endpoint already exists - ID: %s", utils::bufToHexString(foundEndpoint->ep_id, 6).c_str());
        save_to_nvs();
        return std::make_tuple(issuerIdentifier.data(), DUPLICATE);
      }
    }
    else {
      LOG(D, "Issuer does not exist - ID: %s", utils::bufToHexString(issuerIdentifier.data(), 8).c_str());
      save_to_nvs();
      return std::make_tuple(issuerIdentifier.data(), DOES_NOT_EXIST);
    }
  }
  return std::make_tuple(readerData.reader_group_id, DOES_NOT_EXIST);
}

int HK_HomeKit::set_reader_key(std::vector<uint8_t> buf) {
  LOG(D, "Setting reader key: %s", utils::bufToHexString(buf.data(), buf.size()).c_str());
  BerTlv rkrTLv;
  rkrTLv.SetTlv(buf);
  std::vector<uint8_t> readerKey;
  std::vector<uint8_t> uniqueIdentifier;
  if (rkrTLv.GetValue(int_to_hex(kReader_Req_Reader_Private_Key), &readerKey) == TLV_OK && rkrTLv.GetValue(int_to_hex(kReader_Req_Identifier), &uniqueIdentifier) == TLV_OK) {
    LOG(D, "Reader Key: %s", utils::bufToHexString(readerKey.data(), readerKey.size()).c_str());
    LOG(D, "UniqueIdentifier: %s", utils::bufToHexString(uniqueIdentifier.data(), uniqueIdentifier.size()).c_str());
    std::vector<uint8_t> pubKey = getPublicKey(readerKey.data(), readerKey.size());
    LOG(D, "Got reader public key: %s", utils::bufToHexString(pubKey.data(), pubKey.size()).c_str());
    std::vector<uint8_t> x_coordinate = get_x(pubKey.data(), pubKey.size());
    LOG(D, "Got X coordinate: %s", utils::bufToHexString(x_coordinate.data(), x_coordinate.size()).c_str());
    memcpy(readerData.reader_pk_x, x_coordinate.data(), x_coordinate.size());
    memcpy(readerData.reader_pk, pubKey.data(), pubKey.size());
    memcpy(readerData.reader_sk, readerKey.data(), readerKey.size());
    memcpy(readerData.reader_id, uniqueIdentifier.data(), uniqueIdentifier.size());
    std::vector<uint8_t> readeridentifier = utils::getHashIdentifier(readerData.reader_sk, sizeof(readerData.reader_sk), true);
    LOG(D, "Reader GroupIdentifier: %s", utils::bufToHexString(readeridentifier.data(), 8).c_str());
    memcpy(readerData.reader_group_id, readeridentifier.data(), 8);
    bool nvs = save_to_nvs();
    if (nvs) {
      return 0;
    }
    else
      return -1;
  }
  return -1;
}

bool HK_HomeKit::save_to_nvs() {
  uint8_t* buffer = (uint8_t*)malloc(HomeKeyData_ReaderData_size);
  pb_ostream_t ostream = pb_ostream_from_buffer(buffer, HomeKeyData_ReaderData_size);
  bool encodeStatus = pb_encode(&ostream, &HomeKeyData_ReaderData_msg, &readerData);
  LOG(I, "PB ENCODE STATUS: %d", encodeStatus);
  LOG(I, "PB BYTES WRITTEN: %d", ostream.bytes_written);
  esp_err_t set_nvs = nvs_set_blob(nvsHandle, nvsKey, buffer, ostream.bytes_written);
  esp_err_t commit_nvs = nvs_commit(nvsHandle);
  LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  free(buffer);
  return !set_nvs && !commit_nvs;
}