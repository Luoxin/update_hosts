import sys
import traceback
import dns.resolver
import fire
from ping3 import ping
from python_hosts import Hosts, HostsEntry, is_ipv4, is_ipv6
from tqdm import tqdm

from dns_list import dns_service_list


def get_hosts(hosts_path=""):
    if hosts_path == "":
        if sys.platform == "win32":
            hosts_path = "C:\WINDOWS\system32\drivers\etc\hosts"
        elif sys.platform == "linux":
            hosts_path = "/etc/hosts "
        elif sys.platform == "darwin":
            hosts_path = "/ect/hosts"
        elif sys.platform == "cygwin":
            hosts_path = "C:\WINDOWS\system32\drivers\etc\hosts"
        elif sys.platform == "aix":
            hosts_path = "/ect/hosts"
        else:
            print("Please input hosts path")
            hosts_path = input()

    if hosts_path == "":
        return

    return Hosts(path=hosts_path)


def dns_rewrite_update(hosts: Hosts, domain, ip_list: (list, set) = None):
    if len(ip_list) == 0:
        return

    hosts.remove_all_matching(name=domain)
    entry_list = []

    for ip in tqdm(
        ip_list, ncols=100, desc="write hosts {}({})".format(domain, ",".join(ip_list))
    ):
        if is_ipv4(ip):
            entry_type = "ipv4"
        elif is_ipv6(ip):
            entry_type = "ipv6"
        else:
            print("{} type is err".format(ip))
            continue

        entry_list.append(HostsEntry(entry_type=entry_type, address=ip, names=[domain]))

    if len(entry_list) > 0:
        hosts.add(entry_list)


def dns_query(dns_server, domain):
    ip_list = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        A = resolver.query(domain, lifetime=1)
        for i in A.response.answer:
            for j in i.items:
                ip_list.append(j)
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.NoAnswer:
        print("{} has not response".format(dns_server))
    except:
        traceback.print_exc()

    return ip_list


def dns_query_all(domain, all_save: bool = False) -> (set, list):
    if domain.startswith("*."):
        domain = domain.replace("*.", "", 1)

    ip_pool_dns = set()
    ip_pool = set()
    for dns_server in tqdm(
        dns_service_list, ncols=100, desc="dns query {}".format(domain)
    ):
        for ip in dns_query(dns_server, domain):
            ip_pool_dns.add(ip.__str__())

    min_delay = None
    min_delay_ip = None
    for ip in tqdm(ip_pool_dns, ncols=100, desc="ping {}".format(domain)):
        try:
            if is_ipv4(ip) or is_ipv6(ip):
                pass
            else:
                print("{} type is err".format(ip))
                continue
            delay = ping(ip, unit="ms", timeout=1)
            if all_save:
                ip_pool.add(ip)
            elif delay is not None and (min_delay is None or min_delay > delay):
                min_delay = delay
                min_delay_ip = ip
        except OSError:
            pass
        except:
            traceback.print_exc()

    if not all_save and min_delay_ip is not None:
        ip_pool.add(min_delay_ip)
    return ip_pool


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
            "avatars5.githubusercontent.com",
            "avatars4.githubusercontent.com",
            "avatars3.githubusercontent.com",
            "avatars2.githubusercontent.com",
            "avatars1.githubusercontent.com",
            "avatars0.githubusercontent.com",
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
        print("check domain {}".format(domain))
        update_domain(domain, hosts=hosts, all_save=a)
        hosts.write()
        hosts = get_hosts(hosts_path)


def update_from_hosts(hosts_path: str = ""):
    """
    update hosts from hosts
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

    return update_dns(l=domain_list, y=True, a=False)


if __name__ == "__main__":
    fire.Fire({"update": update_dns, "update_hosts": update_from_hosts})
