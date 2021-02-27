from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from pprint import pprint

import aiohttp
import colorama
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity.aio import AzureCliCredential
from azure.mgmt.resource.resources.aio import ResourceManagementClient
from azure.mgmt.resource.subscriptions.aio import SubscriptionClient
from colorama import Fore, Style

colorama.init()


class Logger:
    """Structured logging"""

    level_names = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL']

    level_colors = [
        Fore.BLUE,
        Fore.GREEN,
        Fore.YELLOW,
        Fore.RED,
    ]

    def __init__(self, log_file: str = None):
        if log_file is not None:
            fn = log_file if log_file.endswith('.log') else log_file + '.log'
            self.f = open(fn, '+a')
        else:
            self.f = None
        self.min_file_lvl = 0
        self.min_cli_lvl = 1
        self.enabled = True

    def log(self, lvl: int, msg: str, *args):
        if lvl > len(self.level_names):
            return
        hdr = f'[{self.level_names[lvl]}]'
        clr_hdr = f'{self.level_colors[lvl]}{hdr}{Style.RESET_ALL}'
        timestamp = str(datetime.now())
        # CLI logging
        if lvl >= self.min_cli_lvl and self.enabled:
            print(clr_hdr, msg)
        if lvl >= self.min_file_lvl and self.f is not None and self.enabled:
            self.f.write(f'{timestamp} {hdr} {msg}\n')
        for arg in args:
            if lvl > self.min_cli_lvl and self.enabled:
                pprint(arg)
            if lvl > self.min_file_lvl and self.f is not None and self.enabled:
                self.f.write(json.dumps(arg, sort_keys=True, indent=2) + '\n')

    def debug(self, msg: str, *args):
        self.log(0, msg, *args)

    def info(self, msg: str, *args):
        self.log(1, msg, *args)

    def warning(self, msg: str, *args):
        self.log(2, msg, *args)

    def error(self, msg: str, *args):
        self.log(3, msg, *args)

    def fatal(self, msg: str, *args):
        self.log(4, msg, *args)
        exit(1)


def get_logger(log_file: str):
    """Logging setup"""
    return Logger(log_file)


log = get_logger('core')


def read_backup(filename):
    """Read the backup file"""
    with open(filename, 'r') as f:
        return json.loads(f.read())


class ACIAPIError(Exception):
    pass


@dataclass
class APIC:
    """ACI APIC API wrapper"""
    host: str
    usr: str
    pwd: str

    def __post_init__(self):
        self.jar = aiohttp.CookieJar(unsafe=True)

    async def login(self) -> dict:
        data = {
            "aaaUser": {
                "attributes": {
                    "name": self.usr,
                    "pwd": self.pwd,
                }
            }
        }
        return await self.post('/api/aaaLogin.json', data)

    async def refresh(self) -> dict:
        return await self.get(f'https://{self.host}/api/aaaRefresh.json')

    async def get(self, path: str) -> dict:
        async with aiohttp.ClientSession(cookie_jar=self.jar) as session:
            url = f'https://{self.host}{path}'
            res = await session.get(url, ssl=False)
            if res.status != 200:
                raise ACIAPIError(f'Status code: {res.status}')
            json_res = await res.json()
            err = json_res["imdata"][0].get("error")
            if err is not None:
                raise ACIAPIError(err)
            return json_res

    async def post(self, path: str, data: dict) -> dict:
        async with aiohttp.ClientSession(cookie_jar=self.jar) as session:
            url = f'https://{self.host}{path}'
            res = await session.post(url, json=data, ssl=False)
            if res.status != 200:
                raise ACIAPIError(f'Status code: {res.status}')
            json_res = await res.json()
            err = json_res["imdata"][0].get("error")
            if err is not None:
                raise ACIAPIError(err)
            return json_res


class APICProxy(APIC):
    async def get(self, path: str) -> dict:
        log.debug(f'GET {path}')
        print(f'{Fore.BLUE}GET:{Style.RESET_ALL} {path}')
        print()
        return {}

    async def post(self, path: str, data: dict) -> dict:
        log.debug(f'POST {path}')
        print(f'{Fore.BLUE}POST:{Style.RESET_ALL} {path}')
        print(f'{Fore.BLUE}DATA:{Style.RESET_ALL}')
        print(json.dumps(data, sort_keys=True, indent=2))
        print()
        return data


############################################################
# Azure API wrapper
############################################################


class SubscriptionIDError(Exception):
    pass


class AzureAPI:
    """API client wrapper"""
    api_versions = {}

    def __init__(self, subscription):
        self.subscription = subscription
        self.auth = AzureCliCredential()

    @classmethod
    async def new(cls, subscription) -> AzureAPI:
        subscription = await cls.validate_subscription(subscription)
        api = cls(subscription)
        if len(cls.api_versions) == 0:
            cls.api_versions = await api._get_api_versions()
        return api

    @classmethod
    async def validate_subscription(cls, id: str) -> str:
        try:
            uuid.UUID(id)
            return id
        except ValueError:
            subs = await cls.get_subscriptions()
            for sub in subs:
                if sub['display_name'] == id:
                    return sub['subscription_id']
        raise SubscriptionIDError(id)

    def get_client(self) -> ResourceManagementClient:
        return ResourceManagementClient(self.auth, self.subscription)

    async def get_resources(self) -> list[dict]:
        """Query full resource tree for subscription"""
        log.info('Getting resource list')
        async with self.get_client() as client:
            resources_res = []
            # This is a shallow depth response only
            resources = client.resources.list()
            async for page in resources.by_page():  # type: ignore
                async for resource in page:
                    resources_res.append(resource)
            # Get full depth JSON tree
            all_res = await asyncio.gather(*[
                self.get_resource(client, resource.as_dict())
                for resource in resources_res
            ])
            return [res for res in all_res if res]

    async def get_groups(self) -> list[str]:
        res = []
        async with self.get_client() as client:
            groups = client.resource_groups.list()
            async for group in groups:
                res.append(group.as_dict()['name'])
        return res

    @classmethod
    async def get_subscriptions(cls) -> list[dict[str, str]]:
        res = []
        auth = AzureCliCredential()
        async with SubscriptionClient(auth) as client:
            subs = client.subscriptions.list()
            async for sub in subs:
                res.append(sub.as_dict())
        return res

    async def get_resources_by_group(self, group: str) -> list[dict]:
        """Query full resource tree for this group"""
        log.info(f'Getting resource list for {group}')
        async with self.get_client() as c:
            resources_res = []
            # This is a shallow depth response only
            rs = c.resources.list_by_resource_group(group)  # type: ignore
            async for page in rs.by_page():  # type: ignore
                async for resource in page:
                    resources_res.append(resource)
            # Get full depth JSON tree
            all_res = await asyncio.gather(*[
                self.get_resource(c, resource.as_dict())
                for resource in resources_res
            ])
            return [res for res in all_res if res]

    async def get_resource(self, client, resource) -> dict | None:
        """Query a single resource (full depth)"""
        log.debug(f"Getting resource {resource['name']}")
        resource_type = resource['type']
        api_version = self.api_versions.get(resource_type)
        if api_version is None:
            log.debug(f'cannot find API version for {resource_type}')
            return
        try:
            res = await client.resources.get_by_id(resource['id'], api_version)
            return res.as_dict()
        except Exception:
            id = resource['id']
            log.debug(f'Failed to fetch {id}')

    async def delete_resource(self, client, resource):
        """Delete resource from Azure"""
        name = resource['name'].split('/')[-1]
        log.info(f'Deleting resource {name}')
        resource_type = resource['type']
        api_version = self.api_versions.get(resource_type)
        if api_version is None:
            log.debug(f'cannot find API version for {resource_type}')
            return
        try:
            poller = await client.resources.begin_delete_by_id(
                resource['id'], api_version)
        except HttpResponseError:
            log.warning(f'Unable to delete resource {name}')
            return
        await poller.wait()
        try:
            await client.resources.get_by_id(resource['id'], api_version)
        except ResourceNotFoundError:
            log.info(f'Resource {name} deleted')
            return
        log.error(f'Resource {name} still exists after attempted delete!')

    async def _get_api_versions(self) -> dict[str, list[str]]:
        """Build an index of supported API versions by resource type"""
        log.info('Getting supported API versions from the provider API')
        provider_map = {}
        async with self.get_client() as client:
            async for provider in client.providers.list():
                ns = provider.as_dict()['namespace']
                for resource in provider.as_dict()['resource_types']:
                    resource_type = resource['resource_type']
                    version = resource.get('default_api_version')
                    if version is None:
                        versions = resource.get('api_version', [])
                        if len(versions) > 0:
                            version = version[0]
                    if version is not None:
                        provider_map[f'{ns}/{resource_type}'] = version
        return provider_map


############################################################
# Azure Object DB
############################################################


class NamingError(Exception):
    pass


class TaggingError(Exception):
    pass


class ResourceDB:
    def __init__(self,
                 resources: list[dict] = [],
                 subscription: str = '',
                 filename: str = ''):
        async def fetch_resources() -> list[dict]:
            api = await AzureAPI.new(subscription)
            return await api.get_resources()

        if len(resources) == 0:
            if subscription != '':
                resources = asyncio.run(fetch_resources())
            elif filename != '':
                with open(filename) as f:
                    resources = json.load(f)
        self._by_id: dict[str, dict] = {}
        for resource in resources:
            self._by_id[resource['id']] = resource

    @classmethod
    async def new(cls,
                  resources: list[dict] = [],
                  subscription: str = '',
                  filename: str = '') -> ResourceDB:
        if len(resources) > 0:
            return cls(resources=resources)
        if subscription != '':
            api = await AzureAPI.new(subscription)
            resources = await api.get_resources()
            return cls(resources=resources)
        if filename != '':
            return cls(filename=filename)
        raise Exception('resource list, subscription, or filename required')

    def get(self, input_resource: dict) -> dict | None:
        if input_resource.get('name') is not None:
            return input_resource
        id = input_resource.get('id')
        if id is None:
            return
        return self._by_id.get(id)

    def get_all_nsgs(self) -> list[dict]:
        resources = []
        for resource in self._by_id.values():
            nsg_type = 'Microsoft.Network/networkSecurityGroups'
            if resource.get('type') == nsg_type:
                resources.append(resource)
        return resources

    def get_resource_group(self, group: str) -> list[dict]:
        resources = []
        for id, resource in self._by_id.items():
            if id.split('/')[4] == group:
                resources.append(resource)
        return resources

    def list_groups(self) -> set[str]:
        groups = set()
        for id in self._by_id.keys():
            groups.add(id.split('/')[4])
        return groups

    def get_vnets(self, resources: list[dict]) -> list[dict]:
        vnets = []
        for res in resources:
            if res.get('type') == 'Microsoft.Network/virtualNetworks':
                vnet = self.get(res)
                if vnet is not None:
                    vnets.append(vnet)
        return vnets

    def get_vnet_peers(self, vnet: dict) -> list[dict]:
        peers = []
        for res in vnet['properties'].get('virtualNetworkPeerings', []):
            peer = self.get(res)
            if peer is not None:
                peers.append(peer)
        return peers

    def get_vnet_subnets(self, vnet: dict) -> list[dict]:
        subnets = []
        for res in vnet['properties'].get('subnets', []):
            subnet = self.get(res)
            if subnet is not None:
                subnets.append(subnet)
        return subnets

    def get_subnet_routetable(self, subnet: dict) -> dict | None:
        route_table = subnet['properties'].get('routeTable')
        return self.get(route_table) if route_table else None

    def get_subnet_nsg(self, subnet: dict) -> dict | None:
        nsg = subnet['properties'].get('networkSecurityGroup')
        return self.get(nsg) if nsg else None

    def get_subnet_interfaces(self, subnet: dict) -> list[dict]:
        interfaces = []
        for ip in subnet['properties'].get('ipConfigurations', []):
            ip_id = ip.get('id')
            interface_id = '/'.join(ip_id.split('/')[:9])
            interface = self.get({'id': interface_id})
            if interface is not None:
                interfaces.append(interface)
        return interfaces

    @staticmethod
    def parse_interface_tags(interface: dict) -> dict[str, str]:
        name = interface.get('name', '')
        tags = interface.get('tags', {})
        expected_tags = {'appcode', 'environment', 'servicerole'}
        existing_tags = set(tags.keys())
        missing_tags = expected_tags - existing_tags
        if len(missing_tags) > 0:
            raise TaggingError(f'Int {name} missing tag(s): {missing_tags}')
        return {
            'appcode': tags['appcode'],
            'environment': tags['environment'],
            'servicerole': tags['servicerole'],
        }

    @classmethod
    def parse_subnet_name(cls, subnet_name: str) -> dict[str, str]:
        fmt = '{appcode}-{zone}-{app_short_name}-{env}-{region}-...{snet_num}'
        parts = subnet_name.split('-')
        if len(parts) < 7:
            raise NamingError('Subnet {} is not in expected format {}'.format(
                subnet_name, fmt))
        return {
            'appcode': parts[0],
            'zone': parts[1],
            'app_short_name': parts[2],
            'env': parts[3],
            'region': parts[4],
            'snet_num': parts[-1]
        }

    @classmethod
    def tn_name_from_group(cls, group_name: str) -> str:
        # Per Matt's doc e.g. az-acitest-nonprod-01
        in_fmt = '{prefix}-{id}-{env}...{rg_num}'
        out_fmt = '{prefix}-{id}-{env}-{rg_num}'
        parts = group_name.split('-')
        if len(parts) < 4:
            raise NamingError('Group {} is not in expected format {}'.format(
                group_name, in_fmt))
        return out_fmt.format(prefix=parts[0],
                              id=parts[1],
                              env=parts[2],
                              rg_num=parts[-1])

    @classmethod
    def ap_name_from_subnet(cls, subnet_name: str) -> str:
        # cs = common service
        # ds = dedicated services
        # on = onprem
        # lo = local to the region
        # in = internet
        # {cs|ss|ds|in}-{appcode}-{env}
        out_fmt = 'ds-{appcode}-{env}'
        snet_parts = cls.parse_subnet_name(subnet_name)
        return out_fmt.format(**snet_parts)

    def epg_names_from_subnet(self, subnet: dict) -> list[dict]:
        # cs = common service
        # ds = dedicated services
        # on = onprem
        # lo = local to the region
        # in = internet
        out_fmt = 'ds-{appcode}-{app_short_name}-{env}-{servicerole}-{num}-lo'
        epgs = []
        snet_parts = self.parse_subnet_name(subnet['name'])
        interfaces = self.get_subnet_interfaces(subnet)
        for interface in interfaces:
            try:
                tags = self.parse_interface_tags(interface)
                servicerole = tags['servicerole']
            except TaggingError as e:
                # If all tags aren't there, we only need servicerole
                servicerole = interface.get('tags', {}).get('servicerole')
                if servicerole is None:
                    raise e
            epg_name = out_fmt.format(
                appcode=snet_parts['appcode'],
                app_short_name=snet_parts['app_short_name'],
                env=snet_parts['env'],
                servicerole=servicerole,
                num=snet_parts['snet_num'],
            )
            epgs.append({
                'name': epg_name,
                'subnet': subnet,
                'interface': interface
            })
        return epgs
