include '/usr/local/etc/snort/snort_defaults.lua'
-- require("ips_flow_iat")

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }


ips =
{
    variables = default_variables,
    rules = 'local.rules'
}
