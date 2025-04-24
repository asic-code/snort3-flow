#ifndef _FLOW_FEATURES_H_
#define _FLOW_FEATURES_H_

#include "flow/flow.h"

namespace snort {
class Flow;
class FlowFeatures
{
public:
    // Return inter-arrival time in seconds (or your desired unit)
    static double get_iat(const Flow* flow);
};

}

#endif // _FLOW_FEATURES_H_
