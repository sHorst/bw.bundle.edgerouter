from ipaddress import ip_address, IPv4Address, ip_network
from os.path import join
from bundlewrap.utils import get_file_contents

parameter = {
    'device-type': {'type': 'string', 'default': 'tap', 'direct': True},
    'mode': {'type': 'string', 'default': 'client', 'direct': True},
    'keepalive': {'type': 'string', 'default': None},
    'tun-mtu': {'type': 'int', 'default': None},
    'fragment': {'type': 'int', 'default': None},
    'mssfix': {'type': 'int', 'default': None},
    'client-to-client': {'type': 'bool', 'default': False},

    'persist-key': {'type': 'bool', 'default': False},
    'persist-tun': {'type': 'bool', 'default': False},

    'user': {'type': 'string', 'default': None},
    'group': {'type': 'string', 'default': None},

    'verb': {'type': 'int', 'default': 3},
    'mute': {'type': 'int', 'default': 10},
    'script-security': {'type': 'int', 'default': None},

    'remote': {'type': 'string', 'default': None, 'param_name': 'remote-host', 'direct': True},
    'port': {'type': 'port', 'default': 1194, 'param_name': 'remote-port', 'direct': True},
    'proto': {'type': 'string', 'default': 'udp'},

    'ping': {'type': 'int', 'default': None},
    'ping-restart': {'type': 'int', 'default': None},
    'ping-timer-rem': {'type': 'bool', 'default': None},
    'resolv-retry': {'type': 'int', 'default': None},

    'status': {'type': 'string', 'default': None},
    'ifconfig-pool': {'type': 'string', 'default': None},
    'ifconfig-pool-persist': {'type': 'string', 'default': None},

    'push': {'type': 'array', 'default': []},
    'pull': {'type': 'bool', 'default': None},

    'up': {'type': 'script', 'default': None},
    'down': {'type': 'script', 'default': None},
    'client-connect': {'type': 'script', 'default': None},
    'client-disconnect': {'type': 'script', 'default': None},
    'learn-address': {'type': 'script', 'default': None},

    'ca': {'type': 'file', 'default': None, 'group': 'tls', 'param_name': 'ca-cert-file', 'direct': True},
    'cert': {'type': 'file', 'default': None, 'group': 'tls', 'param_name': 'cert-file', 'direct': True},
    'key': {'type': 'encfile', 'default': None, 'group': 'tls', 'param_name': 'key-file', 'direct': True},
    'dh': {'type': 'string', 'default': None, 'group': 'tls', 'param_name': 'dh-file', 'direct': True},

    'clients': {'type': 'clients', 'default': None, 'group': 'server', 'param_name': 'client', 'direct': True},
    'subnet': {'type': 'string', 'default': None, 'group': 'server', 'direct': True},

    'cipher': {'type': 'string', 'default': None},
    'ncp-ciphers': {'type': 'string', 'default': None},
    'auth': {'type': 'string', 'default': None},

    'passtos': {'type': 'bool', 'default': None},
    'comp-lzo': {'type': 'string', 'default': None},
}


def sort_param(x):
    if x[1].get('direct', False):
        sort_value = x[1].get('param_name', x[0])
    else:
        sort_value = 'openvpn-option "--{}'.format(x[1].get('param_name', x[0]))

    if x[1].get('group', None) is not None:
        return "{}_{}".format(x[1]['group'], sort_value)
    else:
        return sort_value


def sort_interfaces(x):
    int_type = x[1].get('type', 'ethernet')
    int_number = x[0]
    if int_type == 'bridge':
        int_number = int_number[2:]
    elif int_type == 'ethernet':
        int_number = int_number[3:]
    elif int_type == 'openvpn':
        int_number = int_number[4:]

    int_number = int_number.zfill(3)

    return "{}__{}".format(int_type, int_number)


gateway = None

actions = {
    # we need to do it this way, we do not have a working file executable yet
    'create_usr_local_share_misc_folder': {
        'command': 'mkdir -p /usr/local/share/misc',
        'unless': 'test -d /usr/local/share/misc',
    },
}

config_boot_content = []
directories = {}
files = {
    '/usr/local/share/misc/magic.mgc': {
        'content_type': 'binary',
        # since it is missing the file executable it will fail, so we need to not cascade skip
        'cascade_skip': False,
        'needs': [
            'action:create_usr_local_share_misc_folder',
        ]
    },
    # this should work now, since it will find itself
    '/usr/bin/file': {
        'content_type': 'binary',
        'mode': '0755',
        'needs': [
            'file:/usr/local/share/misc/magic.mgc',
        ]
    },
}

pre = ''

if node.metadata.get('edgerouter', {}).get('firewall', False):
    config_boot_content += ['firewall {']
    pre += ' ' * 4
    for key, value in node.metadata['edgerouter']['firewall'].items():
        config_boot_content += [
            '{pre}{key} {value}'.format(
                pre=pre,
                key=key,
                value='enable' if value else 'disable',
            ),
        ]

    pre = pre[:-4]
    config_boot_content += [
        '{}}}'.format(pre)
    ]

config_boot_content += ['interfaces {']
pre += ' ' * 4

for interface, interface_config in sorted(node.metadata.get('interfaces', {}).items(),
                                          key=sort_interfaces
                                          ):
    interface_type = interface_config.get('type', 'ethernet')
    if 'gateway' in interface_config:
        gateway = interface_config['gateway']

    config_boot_content += [
        '{pre}{type} {interface} {{'.format(
            pre=pre,
            type=interface_type,
            interface=interface
        ),
    ]

    interface_options = interface_config.get('options', [])

    pre += ' ' * 4
    for ip in interface_config.get('ip_addresses', []):
        netmask = ip_network('{}/{}'.format(ip, interface_config.get('netmask', '255.255.255.0')), False).prefixlen
        config_boot_content += [
            '{pre}address {ip}/{netmask}'.format(pre=pre, ip=ip, netmask=netmask)
        ]

    if interface_config.get('dhcp', False):
        config_boot_content += [
            '{pre}address dhcp'.format(pre=pre)
        ]

    if 'bridges' in interface_config:
        config_boot_content += [
            '{pre}bridge-group {{'.format(pre=pre),
        ]
        pre += ' ' * 4
        for bridge in interface_config['bridges']:
            config_boot_content += [
                '{pre}bridge {bridge}'.format(pre=pre, bridge=bridge),
            ]
        pre = pre[:-4]
        config_boot_content += [
            '{}}}'.format(pre)
        ]

    if interface_type == 'ethernet':
        config_boot_content += [
            '{pre}duplex auto'.format(pre=pre),
        ]

        if interface_config.get('has_poe', False):
            config_boot_content += [
                '{}poe {{'.format(pre),
                '{}    output {}'.format(pre, 'pthru' if interface_config.get('poe', False) else 'off'),
                '{}}}'.format(pre),
            ]

        interface_options += [
            'speed auto',
        ]

    config_boot_content += map(lambda x: '{}{}'.format(pre, x), interface_options)

    for vlan, vlan_config in sorted(interface_config.get('vlans', {}).items(), key=lambda x: int(x[0])):
        if 'gateway' in vlan_config:
            gateway = vlan_config['gateway']

        config_boot_content += [
            '{}vif {} {{'.format(pre, vlan),
        ]
        pre += ' ' * 4

        if 'bridges' in vlan_config:
            config_boot_content += [
                '{pre}bridge-group {{'.format(pre=pre),
                ]
            pre += ' ' * 4
            for bridge in vlan_config['bridges']:
                config_boot_content += [
                    '{pre}bridge {bridge}'.format(pre=pre, bridge=bridge),
                    ]
            pre = pre[:-4]
            config_boot_content += [
                '{}}}'.format(pre)
            ]

        for ip in vlan_config.get('ip_addresses', []):
            netmask = ip_network('{}/{}'.format(ip, vlan_config.get('netmask', '255.255.255.0')), False).prefixlen
            config_boot_content += [
                '{pre}address {ip}/{netmask}'.format(pre=pre, ip=ip, netmask=netmask)
            ]

        # TODO: correct order
        config_boot_content += map(lambda x: '{}{}'.format(pre, x), vlan_config.get('options', []))
        pre = pre[:-4]
        config_boot_content += [
            '{}}}'.format(pre)
        ]

    pre = pre[:-4]
    config_boot_content += [
        '{}}}'.format(pre)
    ]

config_boot_content += [
    '{pre}loopback lo {{'.format(pre=pre),
    '{}}}'.format(pre),
]

# openvpn
for vpn_name, vpn_config in node.metadata.get('openvpn', {}).items():
    pre = ' ' * 4
    vpn_directory = join('/config', 'auth', vpn_name)

    directories[vpn_directory] = {
        'owner': 'root',
        'group': 'vyattacfg',
        'mode': "2755",
        'needs': [
            # we need file otherwise the bw logic will think it did not upload the correct file
            'file:/usr/bin/file',
        ]
    }

    config_boot_content += [
        '{pre}openvpn {dev} {{'.format(pre=pre, dev=vpn_config['dev']),
        ]
    pre += ' ' * 4

    if 'bridges' in vpn_config:
        config_boot_content += [
            '{}bridge-group {{'.format(pre),
        ]
        pre += ' ' * 4
        for bridge in vpn_config['bridges']:
            config_boot_content += [
                '{}bridge {}'.format(pre, bridge),
            ]

        pre = pre[:-4]
        config_boot_content += [
            '{}}}'.format(pre)
        ]

    if vpn_config.get('mode', 'client') == 'server':
        actions['openvpn_generate_dhparams_{}'.format(vpn_name)] = {
            'command': "openssl dhparam -out {}/dh2048.pem 2048".format(vpn_directory),
            'unless': "test -e {}/dh2048.pem".format(vpn_directory),
            'needs': ['directory:{}'.format(vpn_directory)],
        }

        vpn_config['dh'] = '{}/dh2048.pem'.format(vpn_directory)

    last_group = None
    for param_name, param_config in sorted(parameter.items(), key=sort_param):
        value = vpn_config.get(param_name, param_config['default'])
        param_display_name = param_config.get('param_name', param_name)
        param_type = param_config['type']
        group = param_config.get('group', None)

        if value is not None:
            if group is not None and group != last_group:
                if last_group is not None:
                    pre = pre[:-4]
                    config_boot_content += [
                        '{}}}'.format(pre)
                    ]

                config_boot_content += ['{pre}{group} {{'.format(pre=pre, group=group)]
                pre += ' ' * 4

                last_group = group

            config_lines = []
            if param_type == 'string':
                config_lines += ["{} {}".format(param_display_name, value), ]
            elif param_type == 'int':
                config_lines += ["{} {}".format(param_display_name, str(value)), ]
            elif param_type == 'port':
                if vpn_config.get('mode', 'client') == 'server':
                    param_config['direct'] = False
                    config_lines += ["port {}".format(str(value)), ]
                else:
                    param_config['direct'] = True
                    config_lines += ["{} {}".format(param_display_name, str(value)), ]
            elif param_type == 'bool':
                if value:
                    config_lines += ["{}".format(param_display_name), ]
            elif param_type == 'array':
                if value is not []:
                    for line in value:
                        config_lines += ['{} "{}"'.format(param_display_name, line), ]
            elif param_type == 'script':
                files["{}/{}.sh".format(vpn_directory, param_name)] = {
                    'content': vpn_config[param_name],
                    'content_type': 'text',
                    'owner': "root",
                    'group': 'vyattacfg',
                    'mode': "0755",
                    'needs': [
                        'file:/usr/bin/file',
                    ],
                }

                config_lines += ['{script} {vpn_directory}/{script}.sh'.format(
                    script=param_display_name,
                    vpn_directory=vpn_directory
                ), ]
            elif param_type == 'file':
                files[join(vpn_directory, value)] = {
                    'content': get_file_contents(join(repo.path, "data", "certs", value)),
                    'content_type': 'text',
                    'owner': "root",
                    'group': 'vyattacfg',
                    'mode': "0644",
                    'needs': [
                        'file:/usr/bin/file',
                    ],
                }
                config_lines += ['{} {}/{}'.format(param_display_name, vpn_directory, value), ]
            elif param_type == 'encfile':
                files[join(vpn_directory, value)] = {
                    'content': repo.vault.decrypt_file(join("certs", value)),
                    'content_type': 'text',
                    'owner': "root",
                    'group': 'vyattacfg',
                    'mode': "0644",
                    'needs': [
                        'file:/usr/bin/file',
                    ],
                }
                config_lines += ['{} {}/{}'.format(param_display_name, vpn_directory, value), ]
            elif param_type == 'clients':
                for client, client_config in sorted(value.items(),
                                                    key=lambda x: "{}_{}".format(x[1].get('ip', ''), x[0])
                                                    ):
                    config_lines += [
                        '{} {} {{'.format(param_display_name, client),
                        ]

                    if 'ip' in client_config:
                        config_lines += [
                            '    ip {}'.format(client_config['ip']),
                        ]
                    config_lines += [
                        '}',
                    ]
                pass
            else:
                raise ValueError("unknown parameter type ({}) for {}".format(param_type, param_display_name))

            if config_lines is []:
                continue

            for config_line in config_lines:
                if config_line == '':
                    continue

                if param_config.get('direct', False):
                    config_boot_content += [
                        '{pre}{value}'.format(pre=pre, value=config_line)
                    ]
                else:
                    if " " in config_line:
                        config_boot_content.append('{pre}openvpn-option "--{line}"'.format(pre=pre, line=config_line))
                    else:
                        config_boot_content.append("{pre}openvpn-option --{line}".format(pre=pre, line=config_line))

        # config_boot_content += [
        #     'device-type {}'.format(vpn_config.get('device-type', 'tap')),
        #     'mode {}'.format(vpn_config.get('mode', 'client')),
        #     'remote-host {}'.format(vpn_config.get('remote', '')),
        #     'remote-port {}'.format(vpn_config.get('port', 1194)),
        #
        # ]
    if last_group is not None:
        pre = pre[:-4]
        config_boot_content += [
            '{}}}'.format(pre)
        ]

    # if 'clients' in vpn_config:
    #     config_parameter.append('client-config-dir {}/ccd'.format(vpn_directory))
    #
    #     directories['{}/ccd'.format(vpn_directory)] = {
    #         'owner': 'root',
    #         'group': 'vyattacfg',
    #         'mode': "0755",
    #     }
    #
    #     for client_name, client_config in vpn_config.get('clients', {}).items():
    #         files['{}/ccd/{}'.format(vpn_directory, client_name)] = {
    #             'content': '\n'.join(client_config) + "\n",
    #             'owner': "root",
    #             'group': 'vyattacfg',
    #             'mode': "0444",
    #             'needs': ['pkg_apt:openvpn'],
    #             'triggers': ["svc_systemd:openvpn@{}.service:restart".format(vpn_name)],
    #         }

    pre = pre[:-4]
    config_boot_content += [
        '{}}}'.format(pre)
    ]

for switch, switch_config in sorted(node.metadata.get('edgerouter', {}).get('switches', {}).items(),
                                    key=lambda x: int(x[0])
                                    ):
    # switch
    config_boot_content += [
        '{pre}switch switch{switch} {{'.format(pre=pre, switch=switch),
        ]
    pre += ' ' * 4
    config_boot_content += [
        '{}mtu {}'.format(pre, switch_config.get('mtu', 1500)),
    ]

    if switch_config.get('interfaces', []):
        config_boot_content += [
            '{}switch-port {{'.format(pre),
            ]
        pre += ' ' * 4

        for interface in switch_config.get('interfaces', []):
            config_boot_content += [
                '{}interface {} {{'.format(pre, interface),
                '{}}}'.format(pre)
            ]

        config_boot_content += [
            '{}vlan-aware {}'.format(pre, 'enable' if switch_config.get('vlan_aware', False) else 'disable'),
        ]
        pre = pre[:-4]
        config_boot_content += [
            '{}}}'.format(pre)
        ]

    pre = pre[:-4]
    config_boot_content += [
        '{}}}'.format(pre)
    ]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

# port-forward
if node.metadata.get('port-forward', {}):
    port_forward_config = node.metadata['port-forward']
    config_boot_content += [
        '{pre}port-forward {{'.format(pre=pre),
    ]
    pre += ' ' * 4

    config_boot_content += [
        '{}auto-firewall {}'.format(pre, 'enable' if port_forward_config.get('auto-firewall', False) else 'disable'),
        '{}hairpin-nat {}'.format(pre, 'enable' if port_forward_config.get('hairpin-nat', False) else 'disable'),
        '{}lan-interface {}'.format(pre, port_forward_config.get('lan-interface', '')),
    ]

    for rule, rule_config in sorted(port_forward_config.get('rules', {}).items(), key=lambda x: x[0]):
        config_boot_content += [
            '{pre}rule {number} {{'.format(pre=pre, number=rule),
        ]
        pre += ' ' * 4

        to = rule_config.get('to', ['0.0.0.0', 0])

        config_boot_content += [
            '{}description "{}"'.format(pre, rule_config.get('description', '')),
            '{}forward-to {{'.format(pre,),
            '{}    address {}'.format(pre, to[0]),
            '{}    port {}'.format(pre, to[1]),
            '{}}}'.format(pre),
            '{}original-port {}'.format(pre, rule_config.get('port', 0)),
            '{}protocol {}'.format(pre, rule_config.get('proto', 'tcp')),
        ]

        pre = pre[:-4]
        config_boot_content += [
            '{pre}}}'.format(pre=pre),
        ]
    #     rule 1 {
    #         description ""
    #         forward-to {
    #             address 192.168.178.5
    #             port 80
    #         }
    #         original-port 888
    #         protocol tcp
    #     }
    #     rule 2 {
    #         description ""
    #         forward-to {
    #             address 192.168.178.11
    #             port 80
    #         }
    #         original-port 17588
    #         protocol tcp
    #     }


    config_boot_content += [
        '{}wan-interface {}'.format(pre, port_forward_config.get('wan-interface', '')),
    ]

    pre = pre[:-4]
    config_boot_content += [
        '{pre}}}'.format(pre=pre),
    ]

# service
config_boot_content += [
    '{pre}service {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}gui {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}http-port {port}'.format(pre=pre, port=node.metadata.get('edgerouter', {}).get('http_port', 80)),
    '{pre}https-port {port}'.format(pre=pre, port=node.metadata.get('edgerouter', {}).get('https_port', 443)),
    '{pre}older-ciphers enable'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

# NAT
if node.metadata.get('routes', {}):
    config_boot_content += [
        '{pre}nat {{'.format(pre=pre),
    ]
    pre += ' ' * 4

    for route, route_config in sorted(node.metadata.get('routes', {}).items(), key=lambda x: x[0]):
        if not route_config.get('nat', False):
            continue

        config_boot_content += [
            '{pre}rule {route} {{'.format(pre=pre, route=route),
        ]
        pre += ' ' * 4

        if route_config.get('destination', False):
            config_boot_content += [
                '{pre}description "{description}"'.format(pre=pre, description=route_config.get('description', '')),
                '{pre}destination {{'.format(pre=pre),
                '{pre}    address {destination_addr}'.format(pre=pre, destination_addr=route_config.get('destination', ['', 0])[0]),
                '{pre}    port {destination_port}'.format(pre=pre, destination_port=route_config.get('destination', ['', 0])[1]),
                '{pre}}}'.format(pre=pre),
                '{pre}log disable'.format(pre=pre),
                '{pre}outbound-interface {interface}'.format(pre=pre, interface=route_config.get('out', '')),
                '{pre}protocol {proto}'.format(pre=pre, proto=route_config.get('protocol', 'all')),
                '{pre}type masquerade'.format(pre=pre),
            ]
        else:
            config_boot_content += [
                '{pre}description "{description}"'.format(pre=pre, description=route_config.get('description', '')),
                '{pre}log disable'.format(pre=pre),
                '{pre}outbound-interface {interface}'.format(pre=pre, interface=route_config.get('out', '')),
                '{pre}protocol {proto}'.format(pre=pre, proto=route_config.get('protocol', 'all')),
                '{pre}source {{'.format(pre=pre),
                '{pre}    address {source}'.format(pre=pre, source=route_config.get('source', '')),
                '{pre}}}'.format(pre=pre),
                '{pre}type masquerade'.format(pre=pre),
            ]

        pre = pre[:-4]
        config_boot_content += [
            '{pre}}}'.format(pre=pre),
        ]

    pre = pre[:-4]
    config_boot_content += [
        '{pre}}}'.format(pre=pre),
    ]

# SNMP
config_boot_content += [
    '{pre}snmp {{'.format(pre=pre),
]
pre += ' ' * 4

for community, community_config in node.metadata.get('snmp', {}).get('communities', {}).items():
    config_boot_content += [
        '{pre}community {community} {{'.format(pre=pre, community=community),
    ]
    pre += ' ' * 4
    config_boot_content += [
        '{pre}authorization {access}'.format(pre=pre, access=community_config.get('access', 'ro')),
    ]

    pre = pre[:-4]
    config_boot_content += [
        '{pre}}}'.format(pre=pre),
    ]

config_boot_content += [
    '{pre}contact {contact}'.format(pre=pre, contact=node.metadata.get('snmp', {}).get('contact', '')),
    '{pre}location "{location}"'.format(pre=pre, location=node.metadata.get('snmp', {}).get('location', '')),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

# SSH
config_boot_content += [
    '{pre}ssh {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}port {ssh_port}'.format(pre=pre, ssh_port=node.metadata.get('openssh', {}).get('port', 22)),
    '{pre}protocol-version v2'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}ubnt-discover {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}disable'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}ubnt-discover-server {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}disable'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}unms {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}disable'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}system {{'.format(pre=pre),
]
pre += ' ' * 4
if gateway is not None:
    config_boot_content += [
        '{pre}gateway-address {gw}'.format(pre=pre, gw=gateway),
    ]

config_boot_content += [
    '{pre}host-name {hostname}'.format(pre=pre, hostname=node.hostname),
]

# login
config_boot_content += [
    '{pre}login {{'.format(pre=pre),
]
pre += ' ' * 4

for username, user_attrs in sorted(node.metadata.get('users', {}).items(), key=lambda x: x[0]):
    if not user_attrs.get('delete', False) and user_attrs.get('sudo', False):
        config_boot_content += [
            '{pre}user {username} {{'.format(pre=pre, username=username),
        ]
        pre += ' ' * 4
        config_boot_content += [
            '{pre}authentication {{'.format(pre=pre),
        ]
        pre += ' ' * 4
        config_boot_content += [
            '{pre}encrypted-password {hash}'.format(pre=pre, hash=user_attrs.get('password_hash', '"*"')),
            '{pre}plaintext-password ""'.format(pre=pre),
        ]

        # public keys
        for pk in sorted(user_attrs.get('ssh_pubkeys', []), key=lambda x: x.split(' ', 2)[2]):
            (key_type, key, name) = pk.split(' ', 2)
            config_boot_content += [
                '{pre}public-keys {name} {{'.format(pre=pre, name=name.replace(' ', '_')),
            ]
            pre += ' ' * 4
            config_boot_content += [
                '{pre}key {key}'.format(pre=pre, key=key),
                '{pre}type {key_type}'.format(pre=pre, key_type=key_type),
            ]

            if 'command' in user_attrs:
                config_boot_content += [
                    '{pre}command {command}'.format(pre=pre, command=user_attrs['command']),
                ]

            pre = pre[:-4]
            config_boot_content += [
                '{pre}}}'.format(pre=pre),
            ]

        pre = pre[:-4]
        config_boot_content += [
            '{pre}}}'.format(pre=pre),
            '{pre}full-name "{full_name}"'.format(pre=pre, full_name=user_attrs.get('full_name')),
            '{pre}level admin'.format(pre=pre),
        ]

        pre = pre[:-4]
        config_boot_content += [
            '{pre}}}'.format(pre=pre),
        ]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

for ns in node.metadata.get('nameservers', []):
    config_boot_content += [
        '{pre}name-server {ns}'.format(pre=pre, ns=ns),
    ]
    break  # only one name server

# ntp
config_boot_content += [
    '{pre}ntp {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}server 0.ubnt.pool.ntp.org {{'.format(pre=pre),
    '{pre}}}'.format(pre=pre),
    '{pre}server 1.ubnt.pool.ntp.org {{'.format(pre=pre),
    '{pre}}}'.format(pre=pre),
    '{pre}server 2.ubnt.pool.ntp.org {{'.format(pre=pre),
    '{pre}}}'.format(pre=pre),
    '{pre}server 3.ubnt.pool.ntp.org {{'.format(pre=pre),
    '{pre}}}'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]


# syslog
config_boot_content += [
    '{pre}syslog {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}global {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}facility all {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}level notice'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}facility protocols {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}level debug'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
    '{pre}host 192.168.0.23 {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}facility all {{'.format(pre=pre),
]
pre += ' ' * 4
config_boot_content += [
    '{pre}level info'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

# time-zone
config_boot_content += [
    '{pre}time-zone Europe/Berlin'.format(pre=pre),
]

pre = pre[:-4]
config_boot_content += [
    '{pre}}}'.format(pre=pre),
]

config_boot_content += [
    '',
    '',
    '/* Warning: Do not remove the following line. */',
    '/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:'
    'ipsec@5:nat@3:qos@1:quagga@2:suspend@1:system@4:ubnt-pptp@1:ubnt-udapi-server@1:ubnt-unms@1:ubnt-util@1:vrrp@1:'
    'webgui@1:webproxy@1:zone-policy@1" === */',
    '/* Release version: v1.10.11.5274269.200221.1028 */',
]
# print('\n'.join(config_boot_content))

files['/config/config.boot'] = {
    'content': '\n'.join(config_boot_content) + '\n',
    'mode': '0660',
    'owner': 'root',
    'group': 'vyattacfg',
    'needs': [
        # we need file otherwise the bw logic will think it did not upload the correct file
        'file:/usr/bin/file',
    ]
}
