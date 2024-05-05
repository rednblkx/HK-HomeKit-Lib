#include <hkAttestationAuth.h>

std::vector<unsigned char> HKAttestationAuth::attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd)
{
  BerTlv env1ResTlv;
  env1ResTlv.SetTlv(env1Data);
  std::vector<uint8_t> env1Ndef;
  env1ResTlv.GetValue(int_to_hex(kNDEF_MESSAGE), &env1Ndef);
  NDEFMessage ndefEnv1Ctx = NDEFMessage(env1Ndef.data(), env1Ndef.size());
  auto ndefEnv1Data = ndefEnv1Ctx.unpack();
  auto ndefEnv1Pack = ndefEnv1Ctx.pack();
  NDEFRecord* res_eng = ndefEnv1Ctx.findType("iso.org:18013:deviceengagement");
  uint8_t buf[255];
  uint8_t devEngCbor[255];
  CborEncoder devEng;
  CborEncoder devEngArray;
  cbor_encoder_init(&devEng, devEngCbor, sizeof(devEngCbor), 0);
  CborError i4 = cbor_encoder_create_array(&devEng, &devEngArray, 2);
  CborError i1 = cbor_encode_tag(&devEngArray, CborEncodedCborTag);
  LOG(I, "TEST2 %s", cbor_error_string(i1));
  CborError i2 = cbor_encode_byte_string(&devEngArray, res_eng->data.data(), res_eng->data.size() - 1);
  CborEncoder innerArray;
  cbor_encoder_create_array(&devEngArray, &innerArray, 2);
  LOG(I, "TEST13");
  cbor_encode_byte_string(&innerArray, env1Ndef.data(), env1Ndef.size());
  LOG(I, "TEST14");
  cbor_encode_byte_string(&innerArray, readerCmd.data(), readerCmd.size());
  LOG(I, "TEST15");
  cbor_encoder_close_container(&devEngArray, &innerArray);
  LOG(I, "TEST12");
  cbor_encoder_close_container(&devEng, &devEngArray);
  size_t devSize = cbor_encoder_get_buffer_size(&devEng, devEngCbor);
  ESP_LOG_BUFFER_HEX(TAG, devEngCbor, devSize);
  LOG(I, "TEST5 %d", devSize);
  CborEncoder root;
  cbor_encoder_init(&root, buf, sizeof(buf), 0);
  cbor_encode_tag(&root, CborEncodedCborTag);
  LOG(I, "TEST12");
  cbor_encode_byte_string(&root, devEngCbor, devSize);
  LOG(I, "TEST13");
  size_t rootSize = cbor_encoder_get_buffer_size(&root, buf);
  ESP_LOG_BUFFER_HEX(TAG, buf, rootSize);

  LOG(D, "CBOR MATERIAL DATA: %s", utils::bufToHexString(buf, rootSize).c_str());

  std::vector<uint8_t> salt(32);
  int shaRet = mbedtls_sha256(buf, rootSize, salt.data(), false);

  if (shaRet != 0)
  {
      LOG(E, "SHA256 Failed - %s", mbedtls_high_level_strerr(shaRet));
      return std::vector<unsigned char>();
  }

  LOG(D, "ATTESTATION SALT: %s", utils::bufToHexString(salt.data(), salt.size()).c_str());

  return salt;
}

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> HKAttestationAuth::envelope1Cmd()
{
  uint8_t ctrlFlow[4] = {0x80, 0x3c, 0x40, 0xa0};
  uint8_t ctrlFlowRes[8];
  uint16_t ctrlFlowResLen = 8;
  nfc.inDataExchange(ctrlFlow, sizeof(ctrlFlow), ctrlFlowRes, &ctrlFlowResLen);
  LOG(D, "CTRL FLOW RES LENGTH: %d, DATA: %s", ctrlFlowResLen, utils::bufToHexString(ctrlFlowRes, ctrlFlowResLen).c_str());
  if (ctrlFlowRes[0] == 0x90 && ctrlFlowRes[1] == 0x0)
  { // cla=0x00; ins=0xa4; p1=0x04; p2=0x00; lc=0x07(7); data=a0000008580102; le=0x00
    uint8_t data[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x08, 0x58, 0x01, 0x02, 0x0};
    uint8_t response[4];
    uint16_t responseLength = 4;
    nfc.inDataExchange(data, sizeof(data), response, &responseLength);
    LOG(D, "ENV1.2 RES LENGTH: %d, DATA: %s", responseLength, utils::bufToHexString(response, responseLength).c_str());
    if (response[0] == 0x90 && response[1] == 0x0){
      unsigned char payload[] = {0x15, 0x91, 0x02, 0x02, 0x63, 0x72, 0x01, 0x02, 0x51, 0x02, 0x11, 0x61, 0x63, 0x01, 0x03, 0x6e, 0x66, 0x63, 0x01, 0x0a, 0x6d, 0x64, 0x6f, 0x63, 0x72, 0x65, 0x61, 0x64, 0x65, 0x72};
      unsigned char payload1[] = {0x01};
      unsigned char payload2[] = {0xa2, 0x00, 0x63, 0x31, 0x2e, 0x30, 0x20, 0x81, 0x29};
      auto ndefMessage = NDEFMessage({NDEFRecord("", 0x01, "Hr", payload, sizeof(payload)),
                                      NDEFRecord("nfc", 0x04, "iso.org:18013:nfc", payload1, 1),
                                      NDEFRecord("mdocreader", 0x04, "iso.org:18013:readerengagement", payload2, sizeof(payload2))})
                            .pack();
      LOG(D, "NDEF CMD LENGTH: %d, DATA: %s", ndefMessage.size(), utils::bufToHexString(ndefMessage.data(), ndefMessage.size()).c_str());
      auto envelope1Tlv = utils::simple_tlv(0x53, ndefMessage.data(), ndefMessage.size(), NULL, NULL);
      uint8_t env1Apdu[envelope1Tlv.size() + 6] = {0x00, 0xc3, 0x00, 0x01, static_cast<uint8_t>(envelope1Tlv.size())};
      memcpy(env1Apdu + 5, envelope1Tlv.data(), envelope1Tlv.size());
      LOG(D, "APDU CMD LENGTH: %d, DATA: %s", sizeof(env1Apdu), utils::bufToHexString(env1Apdu, sizeof(env1Apdu)).c_str());
      uint8_t env1Res[128];
      uint16_t env1ResLen = 128;
      nfc.inDataExchange(env1Apdu, sizeof(env1Apdu), env1Res, &env1ResLen);
      LOG(D, "APDU RES LENGTH: %d, DATA: %s", env1ResLen, utils::bufToHexString(env1Res, env1ResLen).c_str());
      if (env1Res[env1ResLen - 2] == 0x90 && env1Res[env1ResLen - 1] == 0x0){
        return std::make_tuple(std::vector<unsigned char>{env1Res, env1Res + env1ResLen}, ndefMessage);
      }
    }
  }
  return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
}

std::vector<unsigned char> HKAttestationAuth::envelope2Cmd(std::vector<uint8_t> &salt)
{
  ISO18013SecureContext secureCtx = ISO18013SecureContext(attestation_exchange_common_secret, salt, 16);

  uint8_t doctype[150];
  CborEncoder docType;
  CborEncoder docMap;
  cbor_encoder_init(&docType, doctype, 150, 0);
  cbor_encoder_create_map(&docType, &docMap, 2);
  cbor_encode_text_stringz(&docMap, "docType");
  cbor_encode_text_stringz(&docMap, "com.apple.HomeKit.1.credential");
  cbor_encode_text_stringz(&docMap, "nameSpaces");
  CborEncoder namespaces;
  CborEncoder homeCred;
  cbor_encoder_create_map(&docMap, &namespaces, 1);
  cbor_encode_text_stringz(&namespaces, "com.apple.HomeKit");
  cbor_encoder_create_map(&namespaces, &homeCred, 1);
  cbor_encode_text_stringz(&homeCred, "credential_id");
  cbor_encode_boolean(&homeCred, false);
  cbor_encoder_close_container(&namespaces, &homeCred);
  cbor_encoder_close_container(&docMap, &namespaces);
  cbor_encoder_close_container(&docType, &docMap);

  ESP_LOG_BUFFER_HEX(TAG, doctype, cbor_encoder_get_buffer_size(&docType, doctype));

  uint8_t docBuf[150];
  CborEncoder doc;
  cbor_encoder_init(&doc, docBuf, sizeof(docBuf), 0);
  CborEncoder docReq;
  cbor_encoder_create_map(&doc, &docReq, 2);
  cbor_encode_text_stringz(&docReq, "docRequests");
  CborEncoder docArray;
  cbor_encoder_create_array(&docReq, &docArray, 1);
  CborEncoder itemMap;
  cbor_encoder_create_map(&docArray, &itemMap, 1);
  cbor_encode_text_stringz(&itemMap, "itemsRequest");
  cbor_encode_tag(&itemMap, CborEncodedCborTag);
  cbor_encode_byte_string(&itemMap, doctype, cbor_encoder_get_buffer_size(&docType, doctype));
  cbor_encoder_close_container(&docArray, &itemMap);
  cbor_encoder_close_container(&docReq, &docArray);
  cbor_encode_text_stringz(&docReq, "version");
  cbor_encode_text_stringz(&docReq, "1.0");
  cbor_encoder_close_container(&doc, &docReq);
  size_t docSize = cbor_encoder_get_buffer_size(&doc, docBuf);
  ESP_LOG_BUFFER_HEX(TAG, docBuf, docSize);

  LOG(V, "CBOR2ENC: %s", utils::bufToHexString(docBuf, docSize).c_str());
  auto encrypted = secureCtx.encryptMessageToEndpoint(std::vector<uint8_t>(docBuf, docBuf + docSize));
  if(encrypted.size() > 0){
    LOG(D, "ENC DATA: %s", utils::bufToHexString(encrypted.data(), encrypted.size()).c_str());

    auto tlv = utils::simple_tlv(0x53, encrypted.data(), encrypted.size());

    unsigned char apdu[6 + tlv.size()] = {0x0, 0xC3, 0x0, 0x0, (unsigned char)tlv.size()};

    memcpy(apdu + 5, tlv.data(), tlv.size());
    LOG(D, "ENV2 APDU - LENGTH: %d, DATA: %s\n", sizeof(apdu), utils::bufToHexString(apdu, sizeof(apdu)).c_str());
    uint16_t newLen = 256;
    uint8_t *env2Res = new unsigned char[256];
    std::vector<unsigned char> attestation_package;
    uint8_t getData[5] = {0x0, 0xc0, 0x0, 0x0, 0x0};
    LOG(D, "ENV2 APDU Len: %d, Data: %s\n", sizeof(apdu), utils::bufToHexString(apdu, sizeof(apdu)).c_str());
    nfc.inDataExchange(apdu, sizeof(apdu), env2Res, &newLen);
    attestation_package.insert(attestation_package.begin(), env2Res, env2Res + newLen - 2);
    LOG(D, "env2Res Len: %d, Data: %s\n", newLen, utils::bufToHexString(env2Res, newLen).c_str());
    while (env2Res[newLen - 2] == 0x61)
    {
      newLen = 256;
      nfc.inDataExchange(getData, sizeof(getData), env2Res, &newLen);
      attestation_package.insert(attestation_package.end(), env2Res, env2Res + newLen - (newLen > 250 ? 2 : 0));
      LOG(D, "env2Res Len: %d, Data: %s\n", newLen, utils::bufToHexString(env2Res, newLen).c_str());
    }
    delete[] env2Res;
    LOG(V, "ATT PKG LENGTH: %d - DATA: %s", attestation_package.size(), utils::bufToHexString(attestation_package.data(), attestation_package.size()).c_str());
    BerTlv data;
    data.SetTlv(attestation_package);
    std::vector<uint8_t> status;
    if (data.GetValue("90", &status) == TLV_OK) {
      std::vector<uint8_t> encryptedMessage;
      data.GetValue("53", &encryptedMessage);
      auto decrypted_message = secureCtx.decryptMessageFromEndpoint(encryptedMessage);
      if(decrypted_message.size() > 0){
        return decrypted_message;
      }
    }
  }
  return std::vector<uint8_t>();
}

std::tuple<HomeKeyData_KeyIssuer *, std::vector<uint8_t>, std::vector<uint8_t>> HKAttestationAuth::verify(std::vector<uint8_t> &decryptedCbor){
  CBOR issuerSignedCbor = CBOR(decryptedCbor.data(), decryptedCbor.size());
  std::vector<uint8_t> protectedHeaders(issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][0].get_bytestring_len());
  std::vector<uint8_t> issuerId(issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][1][4].get_bytestring_len());
  std::vector<uint8_t> data(issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][2].get_bytestring_len());
  uint8_t signature[issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][3].get_bytestring_len()];
  issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][0].get_bytestring(protectedHeaders.data());
  issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][1][4].get_bytestring(issuerId.data());
  issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][2].get_bytestring(data.data());
  issuerSignedCbor["documents"][0]["issuerSigned"]["issuerAuth"][3].get_bytestring(signature);
  CBOR cborTag = CBOR(data.data(), data.size());
  uint8_t deviceInfo[cborTag.get_tag_item().get_bytestring_len()];
  cborTag.get_tag_item().get_bytestring(deviceInfo);
  CBOR cborDevice = CBOR(deviceInfo, sizeof(deviceInfo));
  CBOR cborKeyX = cborDevice["deviceKeyInfo"]["deviceKey"].find_by_key(-2);
  CBOR cborKeyY = cborDevice["deviceKeyInfo"]["deviceKey"].find_by_key(-3);
  uint8_t deviceKeyX[cborKeyX.get_bytestring_len()];
  uint8_t deviceKeyY[cborKeyY.get_bytestring_len()];
  cborKeyX.get_bytestring(deviceKeyX);
  cborKeyY.get_bytestring(deviceKeyY);
  std::vector<uint8_t> devicePubKey;
  devicePubKey.push_back(0x04);
  devicePubKey.insert(devicePubKey.end(), deviceKeyX, deviceKeyX + sizeof(deviceKeyX));
  devicePubKey.insert(devicePubKey.end(), deviceKeyY, deviceKeyY + sizeof(deviceKeyY));

  HomeKeyData_KeyIssuer *foundIssuer = nullptr;

  for (auto *issuer = issuers; issuer != (issuers + issuers_count); ++issuer)
  {
    if (!memcmp(issuer->issuer_id, issuerId.data(), 8)) {
      LOG(D, "Found Issuer: %s", utils::bufToHexString(issuer->issuer_id, 8).c_str());
      foundIssuer = issuer;
    }
  }

  if (foundIssuer != nullptr) {
    CborEncoder package;
    std::vector<uint8_t> packageBuf(strlen("Signature1") + protectedHeaders.size() + data.size() + 8);
    cbor_encoder_init(&package, packageBuf.data(), packageBuf.size(), 0);
    CborEncoder packageArray;
    cbor_encoder_create_array(&package, &packageArray, 4);
    cbor_encode_text_stringz(&packageArray, "Signature1");
    cbor_encode_byte_string(&packageArray, protectedHeaders.data(), protectedHeaders.size());
    cbor_encode_byte_string(&packageArray, {}, 0);
    cbor_encode_byte_string(&packageArray, data.data(), data.size());
    cbor_encoder_close_container(&package, &packageArray);
    size_t package_size = cbor_encoder_get_buffer_size(&package, packageBuf.data());
    LOG(D, "CBOR SIZE: %d", package_size);
    LOG(D, "SIGNED PACKAGE: %s", utils::bufToHexString(packageBuf.data(), package_size).c_str());

    int res = crypto_sign_ed25519_verify_detached(signature, packageBuf.data(), package_size, foundIssuer->issuer_pk);
    if (res) {
      LOG(E, "Failed to verify attestation signature: %d", res);
      return std::make_tuple(foundIssuer, std::vector<uint8_t>(), std::vector<uint8_t>());
    }
    return std::make_tuple(foundIssuer, devicePubKey, std::vector<uint8_t>{deviceKeyX, deviceKeyX + sizeof(deviceKeyX)});
  }
  return std::make_tuple(foundIssuer, std::vector<uint8_t>(), std::vector<uint8_t>());
}

std::tuple<std::tuple<HomeKeyData_KeyIssuer *, std::vector<uint8_t>, std::vector<uint8_t>>, KeyFlow> HKAttestationAuth::attest()
{
  attestation_exchange_common_secret.resize(32);
  attestation_exchange_common_secret.reserve(32);
  esp_fill_random(attestation_exchange_common_secret.data(), 32);
  auto attTlv = utils::simple_tlv(0xC0, attestation_exchange_common_secret.data(), 32, NULL, NULL);
  auto opAttTlv = utils::simple_tlv(0x8E, attTlv.data(), attTlv.size(), NULL, NULL);
  uint8_t attComm[opAttTlv.size() + 1] = {0x0};
  memcpy(attComm + 1, opAttTlv.data(), opAttTlv.size());
  LOG(D, "attComm: %s", utils::bufToHexString(attComm, sizeof(attComm)).c_str());
  auto encryptedCmd = DKSContext.encrypt_command(attComm, sizeof(attComm));

  LOG(V, "encrypted_command: %s", utils::bufToHexString(std::get<0>(encryptedCmd).data(), std::get<0>(encryptedCmd).size()).c_str());
  LOG(V, "calculated_rmac: %s", utils::bufToHexString(std::get<1>(encryptedCmd).data(), std::get<1>(encryptedCmd).size()).c_str());
  uint8_t xchApdu[std::get<0>(encryptedCmd).size() + 6] = {0x84, 0xc9, 0x0, 0x0, (uint8_t)std::get<0>(encryptedCmd).size()};
  memcpy(xchApdu + 5, std::get<0>(encryptedCmd).data(), std::get<0>(encryptedCmd).size());
  LOG(V, "APDU CMD LENGTH: %d, DATA: %s", sizeof(xchApdu), utils::bufToHexString(xchApdu, sizeof(xchApdu)).c_str());
  uint8_t xchRes[16];
  uint16_t xchResLen = 16;
  nfc.inDataExchange(xchApdu, sizeof(xchApdu), xchRes, &xchResLen);
  LOG(D, "APDU RES LENGTH: %d, DATA: %s", xchResLen, utils::bufToHexString(xchRes, xchResLen).c_str());
  HomeKeyData_KeyIssuer* foundIssuer = nullptr;
  if (xchResLen > 2 && xchRes[xchResLen - 2] == 0x90)
  {
    auto env1Data = envelope1Cmd();
    std::vector<uint8_t> env1Res = std::get<0>(env1Data);
    if (env1Res.size() > 2 && env1Res.data()[env1Res.size() - 2] == 0x90)
    {
      auto salt = attestation_salt(std::get<0>(env1Data), std::get<1>(env1Data));
      if(salt.size() > 0){
        auto env2DataDec = envelope2Cmd(salt);
        if (env2DataDec.size() > 0)
        {
          auto verify_result = verify(env2DataDec);
          if (std::get<1>(verify_result).size() > 0) {
            return std::make_tuple(verify_result, kFlowATTESTATION);
          }
        }
      }
    }
  }
  return std::make_tuple(std::make_tuple(foundIssuer, std::vector<uint8_t>(), std::vector<uint8_t>()), kFlowFailed);
}