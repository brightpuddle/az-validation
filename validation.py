#!python3
from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
import traceback
from argparse import ArgumentParser

from core import AzureAPI, NamingError, ResourceDB, TaggingError, get_logger

############################################################
# Common
############################################################

log = get_logger('validation')


class Result:
    def __init__(self, valid=True):
        self.valid = valid

    def update(self, new_result) -> Result:
        if not new_result.valid:
            self.valid = False
        return self

    def info(self, *args, **kwargs) -> Result:
        log.info(*args, **kwargs)
        return self

    def warning(self, *args, **kwargs) -> Result:
        log.warning(*args, **kwargs)
        return self

    def error(self, *args, **kwargs) -> Result:
        log.error(*args, **kwargs)
        return self


def Pass() -> Result:
    return Result(valid=True)


def Fail() -> Result:
    return Result(valid=False)


############################################################
# Azure resource wrappers
############################################################


def with_res(kind: str):
    def wrapper(fn):
        def inner(self):
            log.info(f'Validating {kind} {self.name}')
            res = Pass()
            res = fn(self, res)
            return res

        return inner

    return wrapper


class Resource:
    def __init__(self, db: ResourceDB, cfg):
        self.db = db
        self.cfg = cfg
        self.id = cfg['id']
        self.name = cfg['name']
        self.props = cfg['properties']


class ResourceGroup:
    def __init__(self, db: ResourceDB, resources: list[dict], group: str):
        self.db = db
        self.vnets = [VNet(db, c) for c in db.get_vnets(resources)]
        self.name = group

    def check_name(self) -> Result:
        """RG naming convention complies with tenant parsing"""
        try:
            self.db.tn_name_from_group(self.name)
        except NamingError as e:
            return Fail().error(str(e))
        return Pass()

    def check_only_one_vnet(self) -> Result:
        """Only one vnet per RG"""
        if len(self.vnets) == 1:
            return Pass().info(f'VNet count: {len(self.vnets)} {self.name}')
        return Fail().error(f'VNet count: {len(self.vnets)} {self.name}')

    @with_res('resource group')
    def validate(self, res: Result = Pass()) -> Result:
        res.update(self.check_only_one_vnet())
        res.update(self.check_name())
        for vnet in self.vnets:
            res.update(vnet.validate())
        return res


class VNet(Resource):
    def __init__(self, db: ResourceDB, cfg: dict):
        super().__init__(db, cfg)
        self.peers = [Peer(db, c) for c in db.get_vnet_peers(cfg) if c]
        self.subnets = [Subnet(db, c) for c in db.get_vnet_subnets(cfg) if c]

    def check_remote_gateways(self) -> Result:
        """Peer has useRemoteGateways set"""
        for peer in self.peers:
            if peer.props.get('useRemoteGateways', False):
                return Pass()
        return Fail().warning(
            'useRemoteGateway not set for any peer on vnet {}'.format(
                self.name))

    def check_interface_in_same_rg(self) -> Result:
        """PEP interfaces are in the same RG as VNet"""
        vnet_group = self.id.split('/')[4]
        res = Pass()
        for subnet in self.subnets:
            for interface in subnet.interfaces:
                # This check is only for PEPs
                if '.nic.' not in interface.name:
                    continue
                int_group = interface.id.split('/')[4]
                if int_group != vnet_group:
                    res = Fail().error('group mismatch between {} {}'.format(
                        self.id, interface.id))
        return res

    def check_subnet_zone(self) -> Result:
        """Subnet zone tags are all the same zone"""
        zone_tags = set()
        for subnet in self.subnets:
            try:
                subnet_parts = self.db.parse_subnet_name(subnet.name)
                zone_tags.add(subnet_parts['zone'])
            except NamingError:
                # Failed to parse--this is captured elsewhere
                pass
        if len(zone_tags) > 1:
            return Fail().warning(
                'VNet subnets have multiple zone tags {}'.format(zone_tags))
        return Pass()

    def check_peers(self) -> Result:
        """Peer count is 1"""
        if len(self.peers) == 0:
            return Fail().warning(f'VNet {self.name} is isolated')
        elif len(self.peers) == 1:
            return Pass().info(f'VNet {self.name} only has one peer')
        elif len(self.peers) == 2:
            if self.peers[0].location == self.peers[1].location:
                return Fail().warning(
                    'VNet {} has peers in multiple regions: {}'.format(
                        self.name,
                        str([
                            f'{peer.name}:{peer.location}'
                            for peer in self.peers
                        ])))
            return Pass()
        return Fail().warning(f'VNet {self.name} peer count {len(self.peers)}')

    @with_res('vnet')
    def validate(self, res: Result = Pass()) -> Result:
        res.update(self.check_peers())
        res.update(self.check_subnet_zone())
        res.update(self.check_interface_in_same_rg())
        for peer in self.peers:
            res.update(peer.validate())
        for subnet in self.subnets:
            res.update(subnet.validate())
        return res


class Peer(Resource):
    def __init__(self, db: ResourceDB, cfg: dict):
        super().__init__(db, cfg)
        self.location = cfg.get('location')

    def check_gateway_transit(self) -> Result:
        """allowGatewayTransit *NOT* set for peer"""
        if self.props.get('allowGatewayTransit', False):
            return Fail().warning(
                f'allowGatewayTransit set for peer {self.name}')
        return Pass()

    @with_res('peer')
    def validate(self, res: Result) -> Result:
        res.update(self.check_gateway_transit())
        return res


class Subnet(Resource):
    def __init__(self, db: ResourceDB, cfg: dict):
        super().__init__(db, cfg)
        rt = db.get_subnet_routetable(cfg)
        self.route_table = RouteTable(db, rt) if rt else None
        nsg = db.get_subnet_nsg(cfg)
        self.nsg = NSG(db, nsg) if nsg else None
        self.interfaces = [
            Interface(db, i) for i in db.get_subnet_interfaces(cfg)
        ]

    def check_apic_name_colision(self) -> Result:
        """Subnet name doesn't collide with cAPIC name"""
        if self.nsg is None:
            return Pass()
        capic_nsg_name = f'{self.name}-nsg-01'
        for nsg in self.db.get_all_nsgs():
            if nsg['name'] == capic_nsg_name:
                return Fail().error(
                    'cAPIC name conflict between Subnet {} and NSG {}'.format(
                        self.name, nsg['name']))
        return Pass()

    def check_name(self) -> Result:
        """Subnet name complies with naming convention"""
        try:
            self.db.parse_subnet_name(self.name)
        except NamingError as e:
            return Fail().error(str(e))
        return Pass()

    def check_interface_count(self) -> Result:
        """Subnet has interfaces"""
        count = len(self.interfaces)
        if count == 0:
            return Pass().info(f'Subnet {self.name} has {count} interfaces')
        return Pass()

    def check_is_gateway(self) -> Result:
        """Gateway subnet not present"""
        if 'gatewaysubnet' in self.name.lower():
            return Fail().warning(f'Subnet {self.name} gateway subnet check')
        return Pass()

    def check_delegations(self) -> Result:
        """Delegations are not present"""
        if len(self.props.get('delegations', [])) > 0:
            return Fail().error(f'Subnet {self.name} delegation check')
        return Pass()

    def check_subnet_interface_appcode_tag(self) -> Result:
        """Interface appcode matches subnet appcode"""
        res = Pass()
        try:
            snet_parts = self.db.parse_subnet_name(self.name)
        except NamingError:
            # Already validating bad names elsewhere
            return res
        for interface in self.interfaces:
            try:
                int_tags = self.db.parse_interface_tags(interface.cfg)
            except TaggingError:
                # Already validating bad tags elsewhere
                continue
            if int_tags['appcode'] != snet_parts['appcode']:
                res = Fail().error(
                    'Mismatch between appcode tag in subnet {} and int {}'.
                    format(self.name, interface.name))
        return res

    @with_res('subnet')
    def validate(self, res: Result) -> Result:
        res.update(self.check_is_gateway())
        res.update(self.check_delegations())
        res.update(self.check_interface_count())
        res.update(self.check_name())
        if self.route_table is not None:
            res.update(self.route_table.validate())
        else:
            res.update(Fail().warning('No route table found'))
        if self.nsg is not None:
            res.update(self.nsg.validate())
        else:
            res.update(Fail().warning(f'No NSG found on subnet {self.name}'))

        res.update(self.check_subnet_interface_appcode_tag())

        for interface in self.interfaces:
            res.update(interface.validate())
        return res


class RouteTable(Resource):

    VALID_ROUTES = ['172.25.72.37', '172.29.224.37']

    def check_public_next_hop(self) -> Result:
        """Next hop is *NOT* internet"""
        for route in self.props.get('routes', []):
            if route['properties'].get('nextHopType') == 'Internet':
                return Fail().error(
                    'Internet next hop found for route table {}.'.format(
                        self.name))
            if route['properties'].get('nextHopType') == 'VnetLocal':
                return Fail().error(
                    'VNetLocal next hop found for route table {}.'.format(
                        self.name))
            if 'nextHopIpAddress' not in route['properties']:
                return Fail().error(
                    'Unexpected route type {} in route table {}.'.format(
                        route['properties']['nextHopType'], self.name))
            nh = route['properties']['nextHopIpAddress']
            if ipaddress.ip_address(nh).is_global:
                return Fail().warning(
                    'Public next hop {} found for route table {}'.format(
                        nh, self.name))
        return Pass()

    def check_default_route(self) -> Result:
        """0/0 route in route table"""
        for route in self.props.get('routes', []):
            net = route['properties']['addressPrefix']
            if ipaddress.ip_network(net).prefixlen == 0:
                return Fail().warning(
                    '0/0 route found in route table {}'.format(self.name))
        return Pass()

    def check_valid_next_hop(self) -> Result:
        """At least one next hop in VALID_ROUTES"""
        for route in self.props.get('routes', []):
            nh = route['properties'].get('nextHopIpAddress', '')
            if nh in self.VALID_ROUTES:
                return Pass().info(f'Next hop {nh} found')
        return Fail().error('Expected next hop {} not found'.format(
            self.VALID_ROUTES))

    @with_res('route table')
    def validate(self, res: Result = Pass()) -> Result:
        res.update(self.check_valid_next_hop())
        res.update(self.check_public_next_hop())
        res.update(self.check_default_route())
        return res


class NSG(Resource):
    def check_rule_any_any(self) -> Result:
        """No any to any rules"""
        res = Pass()
        for rule in self.props.get('securityRules', []):
            props = rule.get('properties', {})
            a = props.get('protocol') == '*'
            b = props.get('sourcePortRange') == '*'
            c = props.get('destinationPortRange') == '*'
            d = props.get('sourceAddressPrefix') == '*'
            e = props.get('destinationAddressPrefix') == '*'
            if a and b and c and d and e:
                name = rule.get('name')
                res = Fail().warning(
                    'any to any not supported rule: {} nsg: {}'.format(
                        name, self.name))
        return res

    def check_rule_lb_source_to_any(self) -> Result:
        """No LB to any rules"""
        res = Pass()
        for rule in self.props.get('securityRules', []):
            props = rule.get('properties', {})
            a = props.get('protocol') == '*'
            b = props.get('sourcePortRange') == '*'
            c = props.get('destinationPortRange') == '*'
            d = props.get('sourceAddressPrefix') == 'AzureLoadBalancer'
            e = props.get('destinationAddressPrefix')
            if a and b and c and d and e:
                name = rule.get('name')
                res = Fail().warning(f'rule {name} LB to any not supported')
        return res

    def check_vnet_to_vnet(self) -> Result:
        """No VNet to VNet rules"""
        res = Pass()
        for rule in self.props.get('securityRules', []):
            props = rule.get('properties', {})
            a = props.get('protocol') == '*'
            b = props.get('sourcePortRange') == '*'
            c = props.get('destinationPortRange') == '*'
            d = props.get('sourceAddressPrefix') == 'VirtualNetwork'
            e = props.get('destinationAddressPrefix') == 'VirtualNetwork'
            if a and b and c and d and e:
                name = rule.get('name')
                res = Fail().warning(f'rule {name} Vnet to Vnet not supported')
        return res

    @with_res('nsg')
    def validate(self, res: Result = Pass()) -> Result:
        res.update(self.check_rule_any_any())
        res.update(self.check_rule_lb_source_to_any())
        res.update(self.check_vnet_to_vnet())
        return res


class Interface(Resource):
    def check_tags(self) -> Result:
        try:
            self.db.parse_interface_tags(self.cfg)
        except TaggingError as e:
            servicerole = self.cfg.get('tags', {}).get('servicerole')
            if servicerole is None:
                return Fail().error(
                    'Interface {} missing servicerole tag.'.format(self.name))
            else:
                return Fail().warning(str(e))
        return Pass()

    def check_nsg(self) -> Result:
        """NSG is not attached to interface"""
        if self.props.get('networkSecurityGroup') is not None:
            return Fail().error(f'NSG attached to interface {self.name}')
        return Pass()

    @with_res('interface')
    def validate(self, res):
        res.update(self.check_nsg())
        res.update(self.check_tags())
        return res


############################################################
# Main entry point
############################################################


def get_args():
    parser = ArgumentParser(description='Azure migration validation')
    parser.add_argument('--summary', action='store_true', help='Summary only')

    # Data source
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        '-s',
        '--subscription',
        help='Subscription',
    )
    source.add_argument('-f', '--file', help='Read resources from file')
    source.add_argument(
        '--list-subscriptions',
        action='store_true',
        help='List available subscriptions',
    )

    # Scope
    parser.add_argument(
        '-g',
        '--group',
        help='Resource group',
    )
    parser.add_argument(
        '--list-vnets',
        action='store_true',
        help='List available VNETs',
    )
    parser.add_argument(
        '--list-groups',
        action='store_true',
        help='List available resource groups',
    )
    parser.add_argument(
        '--vnet',
        help='Validate single Vnet',
    )

    args = parser.parse_args()
    return args


async def list_subscriptions():
    log.info('Fetching available subscriptions')
    for sub in await AzureAPI.get_subscriptions():
        print(sub['display_name'], sub['subscription_id'])


def list_groups(db: ResourceDB):
    log.info('Fetching available groups')
    for group in db.list_groups():
        print(group)


def list_vnets(db: ResourceDB):
    log.info('Fetching available vnets')
    for vnet in db.get_vnets(list(db._by_id.values())):
        group = vnet['id'].split('/')[4]
        print('Group:', group)
        print('VNet:', vnet['name'])
        print()


async def get_db(args) -> ResourceDB:
    # Read resources for subscription
    resources = []
    if args.file:
        with open(args.file) as f:
            resources = json.load(f)
    else:
        api = await AzureAPI.new(args.subscription)
        resources = await api.get_resources()

    return ResourceDB(resources)


def validate_vnet(db: ResourceDB, name: str, summary_only=False):
    matched = False
    for cfg in db.get_vnets(list(db._by_id.values())):
        vnet = VNet(db, cfg)
        if vnet.name == name:
            matched = True
            if summary_only:
                # Temporarily disable console logging for summary only
                log.enabled = False
                res = vnet.validate()
                log.enabled = True
            else:
                res = vnet.validate()
            # Disable noise
            if res.valid:
                log.info(f'VNet {name} is ready for migration.')
            else:
                log.warning(f'VNet {name} failed validation.')
    if not matched:
        log.warning(f'VNet {name} not found.')


def validate_group(db: ResourceDB, group: str, summary_only=False):
    # Validate resource group
    rg = ResourceGroup(db, db.get_resource_group(group), group)
    if summary_only:
        # Temporarily disable console logging for summary only
        log.enabled = False
        res = rg.validate()
        log.enabled = True
    else:
        res = rg.validate()
    # Disable noise
    if res.valid:
        log.debug(f'Resource group {group} is ready for migration.')
    else:
        log.debug(f'Resource group {group} failed validation.')


async def main():
    args = get_args()

    # List available subscriptions
    if args.list_subscriptions:
        await list_subscriptions()
        exit(0)

    db = await get_db(args)
    # List available groups
    if args.list_groups:
        list_groups(db)
        exit(0)

    # List available VNETs
    if args.list_vnets:
        list_vnets(db)
        exit(0)

    if args.vnet:
        validate_vnet(db, args.vnet, summary_only=args.summary)
        exit(0)

    if args.group:
        validate_group(db, args.group, summary_only=args.summary)
        exit(0)

    for group in db.list_groups():
        validate_group(db, group, summary_only=args.summary)
        print()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except Exception as e:
        log.error(str(e))
        traceback.print_exc(file=sys.stdout)
