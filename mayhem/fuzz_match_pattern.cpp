#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" int match_pattern(const char* haystack, const char* pattern);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string haystack = provider.ConsumeRandomLengthString(1000);
    std::string pattern = provider.ConsumeRandomLengthString(1000);

    match_pattern(haystack.c_str(), pattern.c_str());

    return 0;
}
