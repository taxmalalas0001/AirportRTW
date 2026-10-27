// Host-side regression checks for untrusted native Wi-Fi request decoding.
#include "../AirportRTW/WCL/WCL.hpp"
#include <assert.h>

int main()
{
    AirportWCL::LqmBeaconUpdate beaconHealth;
    assert(!AirportWCL::makeBeaconUpdate(0, beaconHealth));
    assert(AirportWCL::makeBeaconUpdate(8, beaconHealth));
    assert(beaconHealth.receivedDelta == 8 && beaconHealth.scheduledDelta == 0);
    assert(beaconHealth.beaconValid && beaconHealth.snapshotValid && beaconHealth.countersValid);
    using namespace AirportWCL;
    const uint8_t valid[] = {0, 3, 'a', 'p', '1', 1, 1, 0x82};
    const uint8_t truncated[] = {0, 3, 'a'};
    assert(validIEs(valid, sizeof(valid)));
    assert(!validIEs(truncated, sizeof(truncated)));
    assert(!validIEs(nullptr, 3));

    uint8_t request[0x2cc] = {};
    JoinRequest join;
    // An empty request, an oversized SSID and a multicast AP must all fail.
    assert(!decodeJoin(request, sizeof(request), join));
    request[0x10] = 1;
    request[0x1c] = 3;
    memcpy(request + 0x20, "ap1", 3);
    request[0x214] = 1;
    request[0x21c] = 2;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Open);
    assert(!decodeJoin(request, 0x218, join));
    request[0x1c] = 33;
    assert(!decodeJoin(request, sizeof(request), join));
    request[0x1c] = 3;
    request[0x21c] = 1;
    assert(!decodeJoin(request, sizeof(request), join));

    // SAE needs the passphrase; a WPA2 PMK must never be treated as one.
    request[0x21c] = 2;
    request[0x15] = 0x10; // SAE: upper auth bit 12
    request[0x44] = 63; request[0x48] = 10;
    memset(request + 0x50, 'p', 63);
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::SAE);
    request[0x44] = 64;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x44] = 32; request[0x48] = 6;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x15] = 0; request[0x14] = 8;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Personal);
    request[0x48] = 10;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x44] = 7;
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);

    // Passphrases must work for every PSK AKM set airportd can request:
    // WPA/WPA2 mixed mode and WPA2-PSK advertised together with PSK-SHA256.
    request[0x44] = 12;
    request[0x14] = 0x0a; // WPA_PSK | WPA2_PSK
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x14] = 0x08; request[0x15] = 0x04; // WPA2_PSK | SHA256_PSK
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x15] = 0x01; // unknown auth bit 8 stays invalid
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x15] = 0x10; // WPA2_PSK | WPA3_SAE: transition, joins via WPA2-PSK
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x15] = 0x14; // WPA2_PSK | SHA256_PSK | WPA3_SAE
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalPassphrase);
    request[0x14] = 0x04; request[0x15] = 0x10; // WPA2 (802.1X) | WPA3_SAE
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    request[0x14] = 0x08; request[0x15] = 0;

    // Transition networks fall back to the PSK family even when the AP also
    // advertises PSK-SHA256 or SAE-EXT-KEY. SAE-only stays untouched.
    {
        // RSN v1, group CCMP, 1x pairwise CCMP, AKMs {2,6,8}, caps MFPC.
        uint8_t rsn[] = {48, 28, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4,
                         3, 0, 0, 0x0f, 0xac, 2, 0, 0x0f, 0xac, 6, 0, 0x0f, 0xac, 8,
                         0x80, 0};
        size_t n = selectWPA2TransitionMode(rsn, sizeof(rsn));
        assert(n == sizeof(rsn) - 4 && rsn[1] == 24 && rsn[14] == 2);
        assert(rsn[19] == 2 && rsn[23] == 6 && rsn[24] == 0x80);
        uint8_t ext[] = {48, 24, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4,
                         2, 0, 0, 0x0f, 0xac, 2, 0, 0x0f, 0xac, 24, 0x80, 0};
        n = selectWPA2TransitionMode(ext, sizeof(ext));
        assert(n == sizeof(ext) - 4 && ext[1] == 20 && ext[14] == 1 && ext[19] == 2 && ext[20] == 0x80);
        uint8_t saeOnly[] = {48, 24, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4,
                             2, 0, 0, 0x0f, 0xac, 8, 0, 0x0f, 0xac, 24, 0xc0, 0};
        assert(selectWPA2TransitionMode(saeOnly, sizeof(saeOnly)) == sizeof(saeOnly));
    }
    // A 64-digit hex PSK is the PMK itself; non-hex 64-byte input is invalid.
    request[0x44] = 64;
    memset(request + 0x50, 'a', 64);
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::PersonalHexKey);
    uint8_t pmk[32];
    decodeHexKey(join.key, pmk, sizeof(pmk));
    assert(pmk[0] == 0xaa && pmk[31] == 0xaa);
    request[0x50 + 63] = 'z';
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    // Mixing PSK and 802.1X AKMs stays invalid.
    request[0x44] = 12; request[0x14] = 0x0c; // WPA2 | WPA2_PSK
    assert(decodeJoin(request, sizeof(request), join));
    assert(classifyLegacyAuth(join) == LegacyAuth::Invalid);
    memset(request + 0x50, 'p', 64);
    request[0x14] = 8; request[0x44] = 63;

    uint8_t channels[32] = {};
    channels[36 / 8] |= 1u << (36 % 8);
    assert(scanChannelSelected(channels, true, 36));
    assert(!scanChannelSelected(channels, true, 1));
    assert(!scanChannelSelected(channels, true, 256));
    assert(!probeChannel(true, true, false));
    assert(!probeChannel(true, false, true));

    const uint8_t mac[] = {2, 1, 2, 3, 4, 5};
    const uint8_t multicast[] = {1, 1, 2, 3, 4, 5};
    assert(planMacUpdate(mac, mac, sizeof(mac), false) == MacUpdate::Unchanged);
    assert(planMacUpdate(mac, multicast, sizeof(mac), false) == MacUpdate::Invalid);
    assert(!validCipherKey(6, 31, 0, 0, 0));
    assert(validCipherKey(6, 32, 0, 0, 8));
    NativeChannelInfo native = {};
    assert(!appendChannel(native, 0, false, false, false, false, false));
    assert(appendChannel(native, 36, true, false, false, true, true));
    assert(native.count == 1 && native.channelSpec[0] == 0xd024);
    assert(native.firmwareChannelSpec[0] == native.channelSpec[0]);
    assert(native.supports80MHz[0] == 1);
    native.count = 400;
    assert(!appendChannel(native, 1, false, false, false, false, false));
    const uint64_t tx[] = {10, 20, 30, 40}, rx[] = {1, 2, 3, 4};
    auto counters = makeTrafficCounters(tx, rx, 123);
    assert(counters.infraTx == 100 && counters.infraRx == 10);
    assert(counters.realtimeInfraTx == 70 && counters.realtimeInfraRx == 7);
    assert(counters.timestampNanoseconds == 123);
    return 0;
}
