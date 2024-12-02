#include "simple_tlv.h"

std::vector<unsigned char> simple_tlv(unsigned char tag, const unsigned char* value, size_t valLength, unsigned char* out, size_t* olen) {
  const char* TAG = "simple_tlv";
  uint8_t dataLen[2] = { (unsigned char)valLength };
  bool lenExt = false;
  if (valLength >= 128) {
    uint8_t fb = (1 << 7) + sizeof((unsigned char)valLength);
    dataLen[0] = fb;
    dataLen[1] = (unsigned char)valLength;
    lenExt = true;
  }
  size_t len = sizeof(tag) + valLength + (lenExt ? 2 : 1);
  if (out != NULL && olen != NULL) {
    // memcpy(out, &tag, sizeof(tag));
    std::move(&tag, &tag + sizeof(tag), out);
    // memcpy(out + sizeof(tag), dataLen, lenExt ? 2 : 1);
    std::move(dataLen, dataLen + (lenExt ? 2 : 1), out + sizeof(tag));
    // memcpy(out + sizeof(tag) + (lenExt ? 2 : 1), value, valLength);
    std::move(value, value + valLength, out + sizeof(tag) + (lenExt ? 2 : 1));
    // size_t l = len + *olen;
    // memcpy(olen, &l, sizeof(len));
    *olen += len;
    // ESP_LOGD(TAG, "TLV %x[%d]: %s", tag, valLength, bufToHexString(out + (lenExt ? 3 : 2), len - (lenExt ? 3 : 2)).c_str());
    return std::vector<uint8_t>{};
  }
  else {
    std::vector<unsigned char> buf(len);
    // memcpy(buf.data(), &tag, sizeof(tag));
    std::move(&tag, &tag + sizeof(tag), buf.data());
    // memcpy(buf.data() + sizeof(tag), dataLen, lenExt ? 2 : 1);
    std::move(dataLen, dataLen + (lenExt ? 2 : 1), buf.data() + sizeof(tag));
    // memcpy(buf.data() + sizeof(tag) + (lenExt ? 2 : 1), value, valLength);
    std::move(value, value + valLength, buf.data() + sizeof(tag) + (lenExt ? 2 : 1));
    // ESP_LOGD(TAG, "TLV %x[%d]: %s", tag, valLength, bufToHexString(buf.data() + (lenExt ? 3 : 2), len - (lenExt ? 3 : 2)).c_str());
    return buf;
  }
  return std::vector<uint8_t>{};
}