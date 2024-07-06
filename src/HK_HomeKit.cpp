#include <HK_HomeKit.h>

HK_HomeKit::HK_HomeKit(readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey) : readerData(readerData), nvsHandle(nvsHandle), nvsKey(nvsKey) {
}

std::vector<uint8_t> HK_HomeKit::processResult(std::vector<uint8_t> tlvData) {
  TLV_it operation;
  TLV_it RKR;
  TLV_it DCR;
  TLV rxTlv(NULL, 0);
  rxTlv.unpack(tlvData.data(), tlvData.size());
  operation = rxTlv.find(kReader_Operation);
  RKR = rxTlv.find(kReader_Reader_Key_Request);
  DCR = rxTlv.find(kReader_Device_Credential_Request);
  if (rxTlv.len(operation) > 0) {
  LOG(I, "TLV OPERATION: %d", (*(*operation).val.get()));
    if ((*(*operation).val.get()) == kReader_Operation_Read)
      if ((*RKR).tag == kReader_Reader_Key_Request) {
        LOG(I, "GET READER KEY REQUEST");
        if (readerData.reader_sk.size() > 0) {
          TLV getResSub(NULL, 0);
          getResSub.add(kReader_Res_Key_Identifier, readerData.reader_gid.size(), readerData.reader_gid.data());
          uint8_t subTlv[getResSub.pack_size()];
          getResSub.pack(subTlv);
          LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", sizeof(subTlv), utils::bufToHexString(subTlv, sizeof(subTlv)).c_str());
          TLV getResTlv(NULL, 0);
          getResTlv.add(kReader_Res_Reader_Key_Response, sizeof(subTlv), subTlv);
          uint8_t tlvRes[getResTlv.pack_size()];
          getResTlv.pack(tlvRes);
          LOG(D, "TLV LENGTH: %d, DATA: %s", sizeof(tlvRes), utils::bufToHexString(tlvRes, sizeof(tlvRes)).c_str());
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
        TLV rkResSub(NULL, 0);
        rkResSub.add(kReader_Res_Status, 1, {});
        uint8_t rkSubTlv[rkResSub.pack_size()];
        rkResSub.pack(rkSubTlv);
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", sizeof(rkSubTlv), utils::bufToHexString(rkSubTlv, sizeof(rkSubTlv)).c_str());
        TLV rkResTlv(NULL, 0);
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
      auto state = provision_device_cred(std::vector<uint8_t>((*DCR).val.get(), (*DCR).val.get() + (*DCR).len));
      if (std::get<1>(state) != 99 && std::get<0>(state).size() > 0) {
        BerTlv dcrResSubTlv;
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Issuer_Key_Identifier), std::get<0>(state));
        dcrResSubTlv.Add(int_to_hex(kDevice_Res_Status), int_to_hex(std::get<1>(state)));
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", dcrResSubTlv.GetTlv().size(), dcrResSubTlv.GetTlvAsHexString().c_str());
        BerTlv dcrResTlv;
        dcrResTlv.Add(int_to_hex(kDevice_Credential_Response), dcrResSubTlv.GetTlv());
        LOG(D, "TLV LENGTH: %d, DATA: %s", dcrResTlv.GetTlv().size(), dcrResTlv.GetTlvAsHexString().c_str());
        esp_log_buffer_hex_internal(TAG, dcrResTlv.GetTlv().data(), dcrResTlv.GetTlv().size(), ESP_LOG_INFO);
        return dcrResTlv.GetTlv();
      }
    }
  }
  if ((*(*operation).val.get()) == kReader_Operation_Remove)
    if (rxTlv.len(RKR) > 0) {
      LOG(I, "REMOVE READER KEY REQUEST");
      readerData.reader_gid.clear();
      readerData.reader_id.clear();
      readerData.reader_sk.clear();
      save_to_nvs();
      uint8_t res[] = { 0x7, 0x3, 0x2, 0x1, 0x0 };
      esp_log_buffer_hex_internal(TAG, res, sizeof(res), ESP_LOG_INFO);
      return std::vector<uint8_t>(res, res + sizeof(res));
    }
  return std::vector<uint8_t>();
}

std::tuple<std::vector<uint8_t>, int> HK_HomeKit::provision_device_cred(std::vector<uint8_t> buf) {
  LOG(D, "DCReq Buffer length: %d, data: %s", buf.size(), utils::bufToHexString(buf.data(), buf.size()).c_str());
  BerTlv dcrTlv;
  dcrTlv.SetTlv(buf);
  hkIssuer_t* foundIssuer = nullptr;
  std::vector<uint8_t> issuerIdentifier;
  if (dcrTlv.GetValue(int_to_hex(kDevice_Req_Issuer_Key_Identifier), &issuerIdentifier) == TLV_OK) {
    for (auto& issuer : readerData.issuers) {
      if (std::equal(issuer.issuer_id.begin(), issuer.issuer_id.end(), issuerIdentifier.begin())) {
        LOG(D, "Found issuer - ID: %s", utils::bufToHexString(issuer.issuer_id.data(), 8).c_str());
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      hkEndpoint_t* foundEndpoint = 0;
      std::vector<uint8_t> devicePubKey;
      dcrTlv.GetValue(int_to_hex(kDevice_Req_Public_Key), &devicePubKey);
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> endpointId = utils::getHashIdentifier(devicePubKey.data(), devicePubKey.size(), false);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (std::equal(endpoint.endpoint_id.begin(), endpoint.endpoint_id.end(), endpointId.begin())) {
          LOG(D, "Found endpoint - ID: %s", utils::bufToHexString(endpoint.endpoint_id.data(), 6).c_str());
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == 0) {
        LOG(D, "Adding new endpoint - ID: %s , PublicKey: %s", utils::bufToHexString(endpointId.data(), 6).c_str(), utils::bufToHexString(devicePubKey.data(), devicePubKey.size()).c_str());
        hkEndpoint_t endpoint;
        std::vector<uint8_t> x_coordinate = get_x(devicePubKey.data(), devicePubKey.size());
        std::vector<uint8_t> keyType;
        dcrTlv.GetValue(int_to_hex(kDevice_Req_Key_Type), &keyType);
        endpoint.counter = 0;
        endpoint.key_type = *keyType.data();
        endpoint.last_used_at = 0;
        // endpoint.enrollments.hap = hap;
        endpoint.endpoint_id.insert(endpoint.endpoint_id.begin(), endpointId.begin(), endpointId.end() - 2);
        endpoint.endpoint_pk = devicePubKey;
        endpoint.endpoint_pk_x = x_coordinate;
        foundIssuer->endpoints.emplace_back(endpoint);
        save_to_nvs();
        return std::make_tuple(foundIssuer->issuer_id, SUCCESS);
      }
      else {
        LOG(D, "Endpoint already exists - ID: %s", utils::bufToHexString(foundEndpoint->endpoint_id.data(), 6).c_str());
        save_to_nvs();
        return std::make_tuple(issuerIdentifier, DUPLICATE);
      }
    }
    else {
      LOG(D, "Issuer does not exist - ID: %s", utils::bufToHexString(issuerIdentifier.data(), 8).c_str());
      save_to_nvs();
      return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
    }
  }
  return std::make_tuple(readerData.reader_gid, DOES_NOT_EXIST);
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
    readerData.reader_pk_x = x_coordinate;
    readerData.reader_pk = pubKey;
    readerData.reader_sk = readerKey;
    readerData.reader_id = uniqueIdentifier;
    std::vector<uint8_t> readeridentifier = utils::getHashIdentifier(readerData.reader_sk, true);
    LOG(D, "Reader GroupIdentifier: %s", utils::bufToHexString(readeridentifier.data(), 8).c_str());
    readerData.reader_gid = readeridentifier;
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
  std::vector<uint8_t> cborBuf;
  jsoncons::cbor::encode_cbor(readerData, cborBuf);
  esp_err_t set_nvs = nvs_set_blob(nvsHandle, nvsKey, cborBuf.data(), cborBuf.size());
  esp_err_t commit_nvs = nvs_commit(nvsHandle);
  LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  return !set_nvs && !commit_nvs;
}
