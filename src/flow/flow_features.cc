#include "flow_features.h"
#include "protocols/packet.h"

namespace snort {

double FlowFeatures::get_iat(const Flow* flow)
{
    if (!flow || flow->packet_times.size() < 2) {
        printf("[flow_iat] Plugin called with NULL flow\n");
        return 0.0;
    }

    auto it = flow->packet_times.rbegin();
    uint64_t t1 = *it;
    ++it;
    uint64_t t0 = *it;
    printf("[get_iat] t1: %lu, t0: %lu, diff: %lu\n", t1, t0, t1 - t0);
    // Assuming timestamps are in microseconds, convert to seconds
    // return static_cast<double>(t1 - t0) / 1e6;
    // alternative: use ms
    return static_cast<double>(t1 - t0);
}

}
