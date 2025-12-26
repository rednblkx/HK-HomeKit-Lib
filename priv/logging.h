#pragma once
#if defined(CONFIG_IDF_CMAKE)
#include <esp_log.h>
#define LOG(x, format, ...) ESP_LOG##x(TAG, "%s:%d > " format, __FUNCTION__ , __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#else 
#include <stdio.h>
#define LOG(x, format, ...) printf("%s:%d > " format "\n", __FUNCTION__ , __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#endif
