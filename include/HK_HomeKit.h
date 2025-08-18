#include "HomeKey.h"
#include <functional>
#include <tuple>

class HK_HomeKit
{
  private:
    const char* TAG = "HK_HomeKit";
    std::vector<uint8_t> &tlvData;
    readerData_t& readerData;
    std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key, bool sha256);
    std::vector<uint8_t> get_x(std::vector<uint8_t> &pubKey);
    std::vector<uint8_t> getPublicKey(uint8_t *privKey, size_t len);
    std::tuple<std::vector<uint8_t>, int> provision_device_cred(std::vector<uint8_t> buf);
    const std::function<void(const readerData_t&)> &save_cb;
    const std::function<void()> &remove_key_cb;
    static int esp_rng(void *, uint8_t *buf, size_t len);
    int set_reader_key(std::vector<uint8_t>& buf);
  public:
    HK_HomeKit(readerData_t& readerData, const std::function<void(const readerData_t&)> &save_cb, const std::function<void()> &remove_key_cb, std::vector<uint8_t> &tlvData);
    std::vector<uint8_t> processResult();
};
