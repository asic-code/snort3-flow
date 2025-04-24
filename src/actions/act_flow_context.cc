#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "actions.h"
#include "detection/detect.h"
#include "managers/action_manager.h"
#include "parser/parser.h"
#include "utils/stats.h"

#include "protocols/packet.h"
#include "flow/flow.h"
#include "main/snort_types.h"
#include <arpa/inet.h>

using namespace snort;

#define s_name "flow_context"
#define s_help "Flow context extraction action plugin"

//-------------------------------------------------------------------------
// IPS action
//-------------------------------------------------------------------------

class FlowContextAction : public IpsAction
{
public:
    FlowContextAction() : IpsAction(s_name, nullptr) { }
    void exec(Packet* p, const OptTreeNode* otn) override;
};

void FlowContextAction::exec(Packet* p, const OptTreeNode*)
{
    if (!p || !p->flow)
        return;

    // Example usage: log flow 5-tuple to stderr
    const Flow* flow = p->flow;
    const in_addr src_addr = { flow->get_sip().get_v4() };
    const in_addr dst_addr = { flow->get_dip().get_v4() };
    const char* src = inet_ntoa(src_addr);
    const char* dst = inet_ntoa(dst_addr);

    uint16_t sp = flow->get_sport();
    uint16_t dp = flow->get_dport();
    uint8_t proto = flow->get_proto();

    fprintf(stderr, "[flow_context] %s:%u -> %s:%u proto=%u\n", src, sp, dst, dp, proto);
}

//-------------------------------------------------------------------------

static IpsAction* flow_context_ctor(Module*) { return new FlowContextAction; }
static void flow_context_dtor(IpsAction* p) { delete p; }

static ActionApi flow_context_api
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        nullptr,
        nullptr,
    },
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flow_context_ctor,
    flow_context_dtor
};

const BaseApi* act_flow_context[] =
{
    &flow_context_api.base,
    nullptr
};