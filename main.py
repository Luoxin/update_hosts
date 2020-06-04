import sys
import traceback
import dns.resolver
import fire
from ping3 import ping
from python_hosts import Hosts, HostsEntry, is_ipv4, is_ipv6
from tqdm import tqdm

from dns_list import dns_service_list


def dns_rewrite_update(hosts: Hosts, domain, ip_list: (list, set) = None):
    if len(ip_list) == 0:
        return

    hosts.remove_all_matching(name=domain)
    entry_list = []

    for ip in tqdm(ip_list, desc="write hosts"):
        if is_ipv4(ip):
            entry_type = "ipv4"
        elif is_ipv6(ip):
            entry_type = "ipv6"
        else:
            continue

        entry_list.append(HostsEntry(entry_type=entry_type, address=ip, names=[domain]))

    hosts.add(entry_list)


def dns_query(dns_server, domain):
    ip_list = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        A = resolver.query(domain, lifetime=3)
        for i in A.response.answer:
            for j in i.items:
                ip_list.append(j)
    except dns.exception.Timeout:
        pass
    except:
        traceback.print_exc()

    return ip_list


def dns_query_all(domain) -> (set, list):
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
            delay = ping(ip, unit="ms", timeout=3)
            if delay is not None and (min_delay is None or min_delay > delay):
                min_delay = delay
                min_delay_ip = ip
        except:
            traceback.print_exc()

    if min_delay_ip is not None:
        ip_pool.add(min_delay_ip)
    return ip_pool


def update_domain(domain, hosts_path=""):
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

    hosts = Hosts(path=hosts_path)

    dns_rewrite_update(hosts, domain, dns_query_all(domain))

    hosts.write()


def main(
    domain_list=None, y: bool = False,
):
    if domain_list is None:
        domain_list = [
            "github.githubassets.com",
            "camo.githubusercontent.com",
            "github.map.fastly.net",
            "github.global.ssl.fastly.net",
            "github.com",
            "api.github.com",
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

    print(
        "will check and update domains: {}[y/N]".format(" ".join(domain_list)), end=":"
    )

    if not y:
        y = input()
        if y.lower() != "y":
            return

    for domain in domain_list:
        print("check domain {}".format(domain))
        update_domain(domain)


if __name__ == "__main__":
    fire.Fire({"update": main})
