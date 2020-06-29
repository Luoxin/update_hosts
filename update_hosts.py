import traceback

import dns.resolver
import dns.rdtypes.nsbase
import dns.rdtypes.ANY.RRSIG
import fire
import requests
import simplejson
from ping3 import ping

# from python_hosts import Hosts, HostsEntry, is_ipv4, is_ipv6
from tqdm import tqdm

from dns_list import dns_service_list
from hosts import Hosts, HostsEntry
from utils import is_ipv4, is_ipv6

ncol = 150


def get_hosts(hosts_path=""):
    return Hosts(path=hosts_path)


def dns_rewrite_update(hosts: Hosts, domain, ip_list: (list, set) = None):
    if len(ip_list) == 0:
        print("not query ip for domain {}".format(domain))
        return

    hosts.remove_all_matching(name=domain)
    entry_list = []

    for ip in tqdm(
        ip_list,
        ncols=ncol,
        desc="add hosts to cache {}({})".format(domain, ",".join(ip_list)),
    ):
        if is_ipv4(ip):
            entry_type = "ipv4"
        elif is_ipv6(ip):
            entry_type = "ipv6"
        else:
            entry_type = "comment"

        entry_list.append(HostsEntry(entry_type=entry_type, address=ip, names=[domain]))

    if len(entry_list) > 0:
        hosts.add(entry_list)
    else:
        print("not query ip for domain {}".format(domain))
        return


def dns_query(dns_server: str, domain: str) -> (list, list):
    ip_list = []
    cname_list = []
    try:
        if dns_server.startswith("http"):
            ae = requests.get(
                dns_server,
                params={"name": domain, "type": "A", "ct": "application/dns-json"},
                timeout=1,
            ).json()
            for answer in ae.get("Answer"):
                if answer.get("type") == 1:
                    ip_list.append(str(answer.get("data")))
                elif answer.get("type") == 5:
                    cname_list.append(str(answer.get("data")))
                elif answer.get("type") in [46]:
                    continue
                else:
                    print(answer)

        else:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]

            A = resolver.query(domain, lifetime=1, rdtype=dns.rdatatype.A)

            for i in A.response.answer:
                for j in i.items:
                    ip = j.__str__()

                    if isinstance(j, dns.rdtypes.nsbase.NSBase):
                        cname_list.append(ip)
                        continue

                    if isinstance(j, dns.rdtypes.ANY.RRSIG.RRSIG):
                        # TODO
                        continue

                    if not isinstance(j, dns.rdtypes.IN.A.A):
                        print("j:{},type:{}".format(j, type(j)))
                        continue

                    if is_ipv4(ip) or is_ipv6(ip):
                        pass
                    else:
                        continue
                    ip_list.append(ip)
    except (
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        dns.resolver.NXDOMAIN,
        requests.exceptions.Timeout,
        simplejson.errors.JSONDecodeError,
        requests.exceptions.ConnectionError,
    ):
        pass
    except dns.resolver.NoAnswer:
        print("{} has not response".format(dns_server))
    except:
        traceback.print_exc()

    return ip_list, cname_list


def dns_query_all(domain, all_save: bool = False) -> list:
    if domain.startswith("*."):
        domain = domain.replace("*.", "", 1)

    ip_pool_dns = []
    cnames = []

    for dns_server in tqdm(
        dns_service_list, ncols=ncol, desc="dns query {}".format(domain)
    ):
        ip_list, cname_list = dns_query(dns_server, domain)
        ip_pool_dns.extend(ip_list)
        cnames.extend(cname_list)

    if len(cnames) > 0:
        cnames = set(cnames)
        for cname in cnames:
            ip_pool_dns.extend(dns_query_all(cname, True))

    ip_pool_dns = set(ip_pool_dns)

    min_delay = None
    min_delay_ip = None
    ip_pool = []
    for ip in tqdm(
        ip_pool_dns,
        # ncols=ncol,
        desc="ping {}({})".format(domain, ",".join(ip_pool_dns)),
    ):
        try:
            if is_ipv4(ip) or is_ipv6(ip):
                pass
            else:
                print("{} type is err".format(ip))
                continue

            delay = ping(ip, unit="ms", timeout=1)
            if all_save:
                ip_pool.append(ip)
            elif delay is not None and (min_delay is None or min_delay > delay):
                min_delay = delay
                min_delay_ip = ip
        except OSError:
            pass
        except:
            traceback.print_exc()

    if not all_save and min_delay_ip is not None:
        ip_pool.append(min_delay_ip)

    return list(set(ip_pool))


def update_domain(domain, hosts: Hosts, all_save: bool = False):
    dns_rewrite_update(hosts, domain, dns_query_all(domain, all_save))


def update_dns(l=None, y: bool = False, a: bool = False, hosts_path: str = ""):
    """
    update hosts
    :param hosts_path:
    :param l: domain list, is not input will use github.com
    :param y: agree
    :param a: all host write in hosts
    :return: hosts file path,if not input will use default path
    """

    domain_list = l
    if domain_list is None:
        domain_list = [
            "github.com",
            "api.github.com",
            "github.githubassets.com",
            "camo.githubusercontent.com",
            "github.map.fastly.net",
            "github.global.ssl.fastly.net",
            "raw.githubusercontent.com",
            "user-images.githubusercontent.com",
            "favicons.githubusercontent.com",
            "avatars0.githubusercontent.com",
            "avatars1.githubusercontent.com",
            "avatars2.githubusercontent.com",
            "avatars3.githubusercontent.com",
            "avatars4.githubusercontent.com",
            "avatars5.githubusercontent.com",
        ]

    if isinstance(domain_list, str):
        domain_list = domain_list.replace(" ", "").split(",")
        if len(domain_list) == 0:
            print("can not find domains")
            return
    elif isinstance(domain_list, (list, tuple, set)):
        pass
    else:
        print("invalid domain_list")

    domain_list = list(set(domain_list))

    print(
        "will check and update domains: {} [y/N]".format(" ".join(domain_list)), end=":"
    )

    if not y:
        y = input()
        if y.lower() != "y":
            return
    else:
        print()

    hosts = get_hosts(hosts_path)
    if hosts is None:
        return

    for domain in domain_list:
        print("check domain {} ......".format(domain))
        update_domain(domain, hosts=hosts, all_save=a)

    hosts.write()


def update_from_hosts(hosts_path: str = "", y: bool = False, a: bool = False):
    """
    update hosts from hosts
    :param y: agree
    :param a: all host write in hosts
    :param hosts_path: hosts file path,if not input will use default path
    :return:
    """
    hosts = get_hosts(hosts_path)
    if hosts is None:
        return

    domain_list = []
    for entry in hosts.entries:
        if len(entry.names) > 0:
            domain_list.extend(entry.names)

    return update_dns(l=domain_list, y=y, a=a)


if __name__ == "__main__":
    fire.Fire({"update": update_dns, "update_hosts": update_from_hosts})
