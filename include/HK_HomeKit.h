#include "HomeKey.h"
#include <tuple>
#include <nvs.h>

class HK_HomeKit
{
  private:
    const char* TAG = "HK_HomeKit";
    std::vector<uint8_t> &tlvData;
    readerData_t& readerData;
    nvs_handle& nvsHandle;
    const char* nvsKey = "READERDATA";
    bool save_to_nvs();
    std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key, bool sha256);
    std::vector<uint8_t> get_x(std::vector<uint8_t> &pubKey);
    std::vector<uint8_t> getPublicKey(uint8_t *privKey, size_t len);
    std::tuple<std::vector<uint8_t>, int> provision_device_cred(std::vector<uint8_t> buf);
    static int esp_rng(void *, uint8_t *buf, size_t len);
    int set_reader_key(std::vector<uint8_t>& buf);
  public:
    HK_HomeKit(readerData_t& readerData, nvs_handle& nvsHandle, const char* nvsKey, std::vector<uint8_t> &tlvData);
    std::vector<uint8_t> processResult();
};