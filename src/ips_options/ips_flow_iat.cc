#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "hash/hash_key_operations.h"
#include "flow/flow_features.h"

using namespace snort;

#define s_name "flow_iat"
#define s_help "rule option to check if inter-arrival time (IAT) exceeds a threshold"

static THREAD_LOCAL ProfileStats flowIatPerfStats;

class FlowIatOption : public IpsOption
{
public:
    FlowIatOption(double t) : IpsOption(s_name), threshold(t) {}

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    double threshold;
};

//-------------------------------------------------------------------------
// Option Methods
//-------------------------------------------------------------------------

uint32_t FlowIatOption::hash() const
{
    uint32_t a = std::hash<double>{}(threshold);
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool FlowIatOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const FlowIatOption& rhs = static_cast<const FlowIatOption&>(ips);
    return threshold == rhs.threshold;
}

IpsOption::EvalStatus FlowIatOption::eval(Cursor&, Packet* p)
{
    printf("[flow_iat] Plugin called for flow: %p\n", (void*)p->flow);
    RuleProfile profile(flowIatPerfStats);

    if (!p || !p->flow)
        return NO_MATCH;

    double iat = FlowFeatures::get_iat(p->flow);
    printf("[flow_iat] Flow ID: %p | IAT: %.6f | Threshold: %.6f\n",
           (void*)p->flow, iat, threshold);
    return (iat > threshold) ? MATCH : NO_MATCH;
}

//-------------------------------------------------------------------------
// Module Definition
//-------------------------------------------------------------------------

#define RANGE "0.0:60.0"

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_INTERVAL, RANGE, nullptr,
      "threshold in seconds for inter-arrival time" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class FlowIatModule : public Module
{
public:
    FlowIatModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override { return &flowIatPerfStats; }
    Usage get_usage() const override { return DETECT; }

public:
    double threshold = 0.0;
};

bool FlowIatModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool FlowIatModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~range"));
    threshold = std::stod(v.get_string());
    return true;
}

//-------------------------------------------------------------------------
// API Interface
//-------------------------------------------------------------------------

static Module* mod_ctor() { return new FlowIatModule; }
static void mod_dtor(Module* m) { delete m; }

static IpsOption* flow_iat_ctor(Module* m, OptTreeNode*)
{
    FlowIatModule* mod = static_cast<FlowIatModule*>(m);
    return new FlowIatOption(mod->threshold);
}

static void flow_iat_dtor(IpsOption* o)
{
    delete o;
}

static const IpsApi flow_iat_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        1,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flow_iat_ctor,
    flow_iat_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// Plugin Export
//-------------------------------------------------------------------------

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_flow_iat[] =
#endif
{
    &flow_iat_api.base,
    nullptr
};
