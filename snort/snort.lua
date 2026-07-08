HOME_NET = 'any'
EXTERNAL_NET = 'any'
HTTP_PORTS = '8080 9090'

include '/home/snorty/snort3/etc/snort/snort_defaults.lua'

network = {
    checksum_drop = 'none',
    checksum_eval = 'none',
}

-- TCP reassembly required for flow:established and HTTP payload inspection
stream = {}
stream_ip = {}
stream_icmp = {}
stream_tcp = {}
stream_udp = {}

http_inspect = {}

wizard = default_wizard

binder = {
    { when = { service = 'http' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } },
}

ips = {
    include = '/etc/snort/rules/local.rules',
    variables = {
        nets = {
            HOME_NET = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET,
        },
        ports = {
            HTTP_PORTS = HTTP_PORTS,
        },
    },
}

detection = {
    hyperscan_literals = false,
}

alert_json = {
    file = true,
    limit = 10,
    fields = 'timestamp src_addr dst_addr src_port dst_port proto gid sid rev msg priority class',
}

daq = {
    modules = {
        { name = 'pcap' },
    },
}
