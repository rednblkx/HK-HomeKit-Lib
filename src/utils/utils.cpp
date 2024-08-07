#include "hk-utils.h"

namespace hk_utils
{
  std::string int_to_hex( int i )
  {
    std::stringstream stream;
    stream << std::setfill ('0') << std::setw(2) 
          << std::hex << i;
    return stream.str();
  }

  void pack(const uint8_t* buf, size_t buflen, uint8_t* out, size_t* olen) {
    std::move(buf, buf + buflen, out + *olen);
    *olen += buflen;
  }

  std::string bufToHexString(const uint8_t* buf, size_t len, bool ignoreLevel) {
    std::string result;
    if (buf == NULL || buf == nullptr) {
      return result;
    }
    if (esp_log_level_get("*") >= esp_log_level_t::ESP_LOG_INFO || ignoreLevel) {
      result.reserve(2 * len);
      for (size_t i = 0; i < len; ++i) {
        result.push_back("0123456789ABCDEF"[buf[i] >> 4]);
        result.push_back("0123456789ABCDEF"[buf[i] & 0xF]);
      }
      // ESP_LOGV("bufToHexString", "%s", result.c_str());
    }
    return result;
  }
  std::string bufToHexString(const uint16_t* buf, size_t len, bool ignoreLevel) {
    std::string result;
    if (esp_log_level_get("*") >= esp_log_level_t::ESP_LOG_INFO || ignoreLevel) {
      result.reserve(4 * len); // Reserve space for 4 characters per uint16_t
      for (size_t i = 0; i < len; ++i) {
        result.push_back("0123456789ABCDEF"[(buf[i] >> 12) & 0xF]);
        result.push_back("0123456789ABCDEF"[(buf[i] >> 8) & 0xF]);
        result.push_back("0123456789ABCDEF"[(buf[i] >> 4) & 0xF]);
        result.push_back("0123456789ABCDEF"[buf[i] & 0xF]);
      }
      // ESP_LOGV("bufToHexString", "%s", result.c_str());
    }

    return result;
  }

  std::vector<uint8_t> encodeB64(const uint8_t* src, size_t len) {
    const char* TAG = "encodeB64";
    size_t out_len1 = 0;
    mbedtls_base64_encode(NULL, 0, &out_len1, src, len);
    ESP_LOGV(TAG, "B64 ENCODED LENGTH: %d", out_len1);
    uint8_t dst[out_len1];
    int ret = mbedtls_base64_encode(dst, sizeof(dst), &out_len1, src, len);
    std::vector<uint8_t> enc_vec{ dst, dst + out_len1 };
    ESP_LOGV(TAG, "B64 RESULT: %d", ret);
    ESP_LOGV(TAG, "B64 ENCODED DATA: %s", bufToHexString(dst, out_len1).c_str());
    return enc_vec;
  }

  std::vector<uint8_t> decodeB64(const char* src) {
    const char* TAG = "decodeB64";
    std::string msgCy = src;
    msgCy.erase(std::remove(msgCy.begin(), msgCy.end(), '\\'), msgCy.end());
    size_t out_len1 = 0;
    mbedtls_base64_decode(NULL, 0, &out_len1, (const unsigned char*)msgCy.c_str(), msgCy.size());
    ESP_LOGV(TAG, "B64 DECODED LENGTH: %d", out_len1);
    uint8_t dst[out_len1];
    int ret = mbedtls_base64_decode(dst, sizeof(dst), &out_len1, (const unsigned char*)msgCy.c_str(), msgCy.size());
    std::vector<uint8_t> dec_vec{ dst, dst + out_len1 };
    ESP_LOGV(TAG, "B64 RESULT: %d", ret);

    ESP_LOGV(TAG, "B64 DECODED DATA: %s", bufToHexString(dst, out_len1).c_str());;
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
      ESP_LOGW(TAG, "*** WARNING:  Destination buffer is too small (%d out of %d bytes needed)", sizeof(dst), out_len1);
    else if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
      ESP_LOGW(TAG, "*** WARNING:  Data is not in base-64 format");
    if (ret != 0) {
      return std::vector<uint8_t>();
    }
    return dec_vec;
  }

  std::vector<uint8_t> getHashIdentifier(const uint8_t* key, size_t len, bool sha256) {
    const char* TAG = "getHashIdentifier";
    ESP_LOGV(TAG, "Key: %s, Length: %d, sha256?: %d", bufToHexString(key, len).c_str(), len, sha256);
    std::vector<unsigned char> hashable;
    if (sha256) {
      std::string string = "key-identifier";
      hashable.insert(hashable.begin(), string.begin(), string.end());
    }
    hashable.insert(hashable.end(), key, key + len);
    ESP_LOGV(TAG, "Hashable: %s", bufToHexString(&hashable.front(), hashable.size()).c_str());
    uint8_t hash[32];
    if (sha256) {
      mbedtls_sha256(&hashable.front(), hashable.size(), hash, 0);
    }
    else {
      mbedtls_sha1(&hashable.front(), hashable.size(), hash);
    }
    ESP_LOGD(TAG, "HashIdentifier: %s", bufToHexString(hash, (sha256 ? 8 : 6)).c_str());
    return std::vector<uint8_t>{hash, hash + (sha256 ? 8 : 6)};
  }
  std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t> &key, bool sha256) {
    const char* TAG = "getHashIdentifier";
    ESP_LOGV(TAG, "Key: %s, Length: %d, sha256?: %d", bufToHexString(key.data(), key.size()).c_str(), key.size(), sha256);
    std::vector<unsigned char> hashable;
    if (sha256) {
      std::string string = "key-identifier";
      hashable.insert(hashable.begin(), string.begin(), string.end());
    }
    hashable.insert(hashable.end(), key.begin(), key.end());
    ESP_LOGV(TAG, "Hashable: %s", bufToHexString(&hashable.front(), hashable.size()).c_str());
    std::vector<uint8_t> hash(32);
    if (sha256) {
      mbedtls_sha256(&hashable.front(), hashable.size(), hash.data(), 0);
    }
    else {
      mbedtls_sha1(&hashable.front(), hashable.size(), hash.data());
    }
    ESP_LOGD(TAG, "HashIdentifier: %s", bufToHexString(hash.data(), 32).c_str());
    return hash;
  }

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
      ESP_LOGD(TAG, "TLV %x[%d]: %s", tag, valLength, bufToHexString(out + (lenExt ? 3 : 2), len - (lenExt ? 3 : 2)).c_str());
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
      ESP_LOGD(TAG, "TLV %x[%d]: %s", tag, valLength, bufToHexString(buf.data() + (lenExt ? 3 : 2), len - (lenExt ? 3 : 2)).c_str());
      return buf;
    }
    return std::vector<uint8_t>{};
  }
}