#include <HK_HomeKit.h>
#include "TLV8.h"
#include "logging.h"
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <esp_random.h>
#include <mbedtls/error.h>

HK_HomeKit::HK_HomeKit(readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey, std::vector<uint8_t>& tlvData) : tlvData(tlvData), readerData(readerData), nvsHandle(nvsHandle), nvsKey(nvsKey) {
}

std::vector<uint8_t> HK_HomeKit::processResult() {
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
          LOG(D, "SU-TLV LENGT:  %d, DATA: %s", sizeof(subTlv), red_log::bufToHexString(subTlv, sizeof(subTlv)).c_str());
          TLV getResTlv(NULL, 0);
          getResTlv.add(kReader_Res_Reader_Key_Response, sizeof(subTlv), subTlv);
          uint8_t tlvRes[getResTlv.pack_size()];
          getResTlv.pack(tlvRes);
          LOG(D, "TLV LENGTH: %d, DATA: %s", sizeof(tlvRes), red_log::bufToHexString(tlvRes, sizeof(tlvRes)).c_str());
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
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", sizeof(rkSubTlv), red_log::bufToHexString(rkSubTlv, sizeof(rkSubTlv)).c_str());
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
        TLV dcrResSubTlv(NULL, 0);
        dcrResSubTlv.add(kDevice_Res_Issuer_Key_Identifier, std::get<0>(state).size(), std::get<0>(state).data());
        dcrResSubTlv.add(kDevice_Res_Status, std::get<1>(state));
        uint8_t packedRes[dcrResSubTlv.pack_size()];
        dcrResSubTlv.pack(packedRes);
        LOG(D, "SUB-TLV LENGTH: %d", dcrResSubTlv.pack_size());
        TLV dcrResTlv(NULL, 0);
        dcrResSubTlv.add(kDevice_Credential_Response, sizeof(packedRes), packedRes);
        LOG(D, "TLV LENGTH: %d", dcrResTlv.pack_size());
        std::vector<uint8_t> result(dcrResTlv.pack_size());
        dcrResTlv.pack(result.data());
        return result;
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

int HK_HomeKit::esp_rng(void*, uint8_t* buf, size_t len)
{
  esp_fill_random(buf, len);
  return 0;
}

std::vector<uint8_t> HK_HomeKit::get_x(std::vector<uint8_t> &pubKey)
{
  mbedtls_ecp_group grp;
  mbedtls_ecp_point point;
  mbedtls_ecp_point_init(&point);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  int ecp_read = mbedtls_ecp_point_read_binary(&grp, &point, pubKey.data(), pubKey.size());
  if(ecp_read != 0)
    LOG(E, "ecp_read - %s", mbedtls_high_level_strerr(ecp_read));
  size_t buffer_size_x = mbedtls_mpi_size(&point.private_X);
  std::vector<uint8_t> X(buffer_size_x);
  int ecp_write = mbedtls_mpi_write_binary(&point.private_X, X.data(), buffer_size_x);
  if(ecp_write != 0)
    LOG(E, "ecp_write - %s", mbedtls_high_level_strerr(ecp_write));
  LOG(V, "PublicKey: %s, X Coordinate: %s", red_log::bufToHexString(pubKey.data(), pubKey.size()).c_str(), red_log::bufToHexString(X.data(), X.size()).c_str());
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&point);
  return X;
}

std::vector<uint8_t> HK_HomeKit::getPublicKey(uint8_t *privKey, size_t len)
{
  mbedtls_ecp_keypair keypair;
  mbedtls_ecp_keypair_init(&keypair);
  int ecp_key = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &keypair, privKey, len);
  int ret = mbedtls_ecp_mul(&keypair.private_grp, &keypair.private_Q, &keypair.private_d, &keypair.private_grp.G, esp_rng, NULL);
  if(ecp_key != 0){
    LOG(E, "ecp_write_1 - %s", mbedtls_high_level_strerr(ecp_key));
    return std::vector<uint8_t>();
  }
  if (ret != 0) {
    LOG(E, "mbedtls_ecp_mul - %s", mbedtls_high_level_strerr(ret));
    return std::vector<uint8_t>();
  }
    size_t olenPub = 0;
  std::vector<uint8_t> readerPublicKey(MBEDTLS_ECP_MAX_BYTES);
  mbedtls_ecp_point_write_binary(&keypair.private_grp, &keypair.private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olenPub, readerPublicKey.data(), readerPublicKey.capacity());
  readerPublicKey.resize(olenPub);

  // Cleanup
  mbedtls_ecp_keypair_free(&keypair);
  return readerPublicKey;
}

std::vector<uint8_t> HK_HomeKit::getHashIdentifier(const std::vector<uint8_t>& key, bool sha256) {
  const char* TAG = "getHashIdentifier";
  // ESP_LOGV(TAG, "Key: %s, Length: %d, sha256?: %d", bufToHexString(key.data(), key.size()).c_str(), key.size(), sha256);
  std::vector<unsigned char> hashable;
  if (sha256) {
    std::string string = "key-identifier";
    hashable.insert(hashable.begin(), string.begin(), string.end());
  }
  hashable.insert(hashable.end(), key.begin(), key.end());
  // ESP_LOGV(TAG, "Hashable: %s", bufToHexString(&hashable.front(), hashable.size()).c_str());
  std::vector<uint8_t> hash(32);
  if (sha256) {
    mbedtls_sha256(&hashable.front(), hashable.size(), hash.data(), 0);
  }
  else {
    mbedtls_sha1(&hashable.front(), hashable.size(), hash.data());
  }
  // ESP_LOGD(TAG, "HashIdentifier: %s", bufToHexString(hash.data(), 32).c_str());
  return hash;
}

std::tuple<std::vector<uint8_t>, int> HK_HomeKit::provision_device_cred(std::vector<uint8_t> buf) {
  LOG(D, "DCReq Buffer length: %d, data: %s", buf.size(), red_log::bufToHexString(buf.data(), buf.size()).c_str());
  TLV dcrTlv;
  dcrTlv.unpack(buf.data(), buf.size());
  hkIssuer_t* foundIssuer = nullptr;
  TLV_it tlvIssuerId = dcrTlv.find(kDevice_Req_Issuer_Key_Identifier);
  std::vector<uint8_t> issuerIdentifier((*tlvIssuerId).val.get(), (*tlvIssuerId).val.get() + (*tlvIssuerId).len);
  if (issuerIdentifier.size() > 0) {
    for (auto& issuer : readerData.issuers) {
      if (std::equal(issuer.issuer_id.begin(), issuer.issuer_id.end(), issuerIdentifier.begin())) {
        LOG(D, "Found issuer - ID: %s", red_log::bufToHexString(issuer.issuer_id.data(), 8).c_str());
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      hkEndpoint_t* foundEndpoint = 0;
      TLV_it tlvDevicePubKey = dcrTlv.find(kDevice_Req_Public_Key);
      std::vector<uint8_t> devicePubKey((*tlvDevicePubKey).val.get(), (*tlvDevicePubKey).val.get() + (*tlvDevicePubKey).len);
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> endpointId = getHashIdentifier(devicePubKey, false);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (std::equal(endpoint.endpoint_id.begin(), endpoint.endpoint_id.end(), endpointId.begin())) {
          LOG(D, "Found endpoint - ID: %s", red_log::bufToHexString(endpoint.endpoint_id.data(), 6).c_str());
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == 0) {
        LOG(D, "Adding new endpoint - ID: %s , PublicKey: %s", red_log::bufToHexString(endpointId.data(), 6).c_str(), red_log::bufToHexString(devicePubKey.data(), devicePubKey.size()).c_str());
        hkEndpoint_t endpoint;
        std::vector<uint8_t> x_coordinate = get_x(devicePubKey);
        TLV_it tlvKeyType = dcrTlv.find(kDevice_Req_Key_Type);
        std::vector<uint8_t> keyType((*tlvKeyType).val.get(), (*tlvKeyType).val.get() + (*tlvKeyType).len);
        endpoint.counter = 0;
        endpoint.key_type = *keyType.data();
        endpoint.last_used_at = 0;
        // endpoint.enrollments.hap = hap;
        endpoint.endpoint_id = std::vector<uint8_t>{ endpointId.begin(), endpointId.begin() + 6 };
        endpoint.endpoint_pk = devicePubKey;
        endpoint.endpoint_pk_x = x_coordinate;
        foundIssuer->endpoints.emplace_back(endpoint);
        save_to_nvs();
        return std::make_tuple(foundIssuer->issuer_id, SUCCESS);
      }
      else {
        LOG(D, "Endpoint already exists - ID: %s", red_log::bufToHexString(foundEndpoint->endpoint_id.data(), 6).c_str());
        save_to_nvs();
        return std::make_tuple(issuerIdentifier, DUPLICATE);
      }
    }
    else {
      LOG(D, "Issuer does not exist - ID: %s", red_log::bufToHexString(issuerIdentifier.data(), 8).c_str());
      save_to_nvs();
      return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
    }
  }
  return std::make_tuple(readerData.reader_gid, DOES_NOT_EXIST);
}

int HK_HomeKit::set_reader_key(std::vector<uint8_t> buf) {
  LOG(D, "Setting reader key: %s", red_log::bufToHexString(buf.data(), buf.size()).c_str());
  TLV rkrTLv(NULL, 0);
  rkrTLv.unpack(buf.data(), buf.size());
  TLV_it tlvReaderKey = rkrTLv.find(kReader_Req_Reader_Private_Key);
  std::vector<uint8_t> readerKey((*tlvReaderKey).val.get(), (*tlvReaderKey).val.get() + (*tlvReaderKey).len);
  TLV_it tlvUniqueId = rkrTLv.find(kReader_Req_Identifier);
  std::vector<uint8_t> uniqueIdentifier((*tlvUniqueId).val.get(), (*tlvUniqueId).val.get() + (*tlvUniqueId).len);
  if (readerKey.size() > 0 && uniqueIdentifier.size() > 0) {
    LOG(D, "Reader Key: %s", red_log::bufToHexString(readerKey.data(), readerKey.size()).c_str());
    LOG(D, "UniqueIdentifier: %s", red_log::bufToHexString(uniqueIdentifier.data(), uniqueIdentifier.size()).c_str());
    std::vector<uint8_t> pubKey = getPublicKey(readerKey.data(), readerKey.size());
    LOG(D, "Got reader public key: %s", red_log::bufToHexString(pubKey.data(), pubKey.size()).c_str());
    std::vector<uint8_t> x_coordinate = get_x(pubKey);
    LOG(D, "Got X coordinate: %s", red_log::bufToHexString(x_coordinate.data(), x_coordinate.size()).c_str());
    readerData.reader_pk_x = x_coordinate;
    readerData.reader_pk = pubKey;
    readerData.reader_sk = readerKey;
    readerData.reader_id = uniqueIdentifier;
    std::vector<uint8_t> readeridentifier = getHashIdentifier(readerData.reader_sk, true);
    LOG(D, "Reader GroupIdentifier: %s", red_log::bufToHexString(readeridentifier.data(), 8).c_str());
    readerData.reader_gid = std::vector<uint8_t>{readeridentifier.begin(), readeridentifier.begin() + 8};
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
  std::vector<uint8_t> data = json::to_msgpack(readerData);
  esp_err_t set_nvs = nvs_set_blob(nvsHandle, nvsKey, data.data(), data.size());
  esp_err_t commit_nvs = nvs_commit(nvsHandle);
  LOG(D, "NVS SET STATUS: %s", esp_err_to_name(set_nvs));
  LOG(D, "NVS COMMIT STATUS: %s", esp_err_to_name(commit_nvs));
  return !set_nvs && !commit_nvs;
}
