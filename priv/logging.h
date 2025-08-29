#pragma once
#include <esp_log.h>

#define LOG(x, format, ...) ESP_LOG##x(TAG, "%s:%d > " format, __FUNCTION__ , __LINE__ __VA_OPT__(, ) __VA_ARGS__)
