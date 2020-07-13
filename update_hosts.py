import traceback
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.nsbase
import dns.resolver
import fire
import requests
import simplejson
from cacheout import Cache
from ping3 import ping
from rich.console import Console
from rich.progress import track
from rich.table import Table

from dns_list import dns_service_list
from hosts import Hosts, HostsEntry
from utils import is_ipv4, is_ipv6

console = Console()

cache = Cache()


def get_hosts(hosts_path=""):
    return Hosts(path=hosts_path)


def dns_rewrite_update(hosts: Hosts, domain, ip_list: (list, set) = None):
    if len(ip_list) == 0:
        console.print("not query ip for domain [red]{}[/red]".format(domain))
        return

    hosts.remove_all_matching(name=domain)
    entry_list = []

    console.print(
        "will add hosts to cache [yellow]{}[yellow]([green]{}[/green])".format(
            domain, ",".join(ip_list)
        )
    )

    for ip in track(
            ip_list,
            description="add hosts to cache [yellow]{}[/yellow]".format(domain),
            console=console,
            transient=True,
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
        console.print("not query ip for domain [red]{}[/red]".format(domain))
        return


def dns_query(dns_server: str, domain: str) -> (list, list):
    ip_list = []
    cname_list = []
    try:
        if dns_server.startswith("http"):
            ae = requests.get(
                dns_server,
                params={"name": domain, "type": "A", "ct": "application/dns-json"},
                timeout=5,
            ).json()

            if isinstance(ae.get("Answer"), (list, set, tuple)):
                for answer in ae.get("Answer"):
                    t = answer.get("type")
                    if t == 1:
                        ip_list.append(str(answer.get("data")))
                    elif t == 5:
                        cname_list.append(str(answer.get("data")))
                    elif t in [46]:
                        continue
                    else:
                        console.print(answer)

        else:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]

            A = resolver.query(domain, lifetime=5, rdtype=dns.rdatatype.A)

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
                        console.print("j:{},type:{}".format(j, type(j)))
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
        pass
    except:
        console.print_exception()

    return ip_list, cname_list


def dns_query_all(domain, all_save: bool = False) -> list:
    if domain.startswith("*."):
        domain = domain.replace("*.", "", 1)

    if cache.get(key=domain) is not None:
        return cache.get(key=domain)

    ip_pool_dns = []
    cnames = []

    for dns_server in track(
            dns_service_list,
            description="dns query [yellow]{}[/yellow]".format(domain),
            console=console,
            transient=True,
    ):
        ip_list, cname_list = dns_query(dns_server, domain)
        ip_pool_dns.extend(ip_list)
        cnames.extend(cname_list)

    if len(cnames) > 0:
        cnames = set(cnames)
        for cname in cnames:
            ip_pool_dns.extend(dns_query_all(cname, True))

    ip_pool_dns = set(ip_pool_dns)

    console.print(
        "will ping [yellow]{}[/yellow]([green]{}[/green])".format(
            domain, ",".join(ip_pool_dns)
        )
    )

    min_delay = None
    min_delay_ip = None
    ip_pool = []
    for ip in track(
            ip_pool_dns,
            description="ping [yellow]{}[/yellow]".format(domain),
            console=console,
            transient=True,
    ):
        try:
            if is_ipv4(ip) or is_ipv6(ip):
                pass
            else:
                console.print("{} type is err".format(ip))
                continue

            delay = ping(ip, unit="ms", timeout=5)
            if all_save:
                ip_pool.append(ip)
            elif delay is not None and (min_delay is None or min_delay > delay):
                min_delay = delay
                min_delay_ip = ip
        except OSError:
            pass
        except:
            console.print_exception()

    if not all_save and min_delay_ip is not None:
        ip_pool.append(min_delay_ip)

    cache.set(domain, list(set(ip_pool)))
    return cache.get(domain)


def update_domain(domain, hosts: Hosts, all_save: bool = False):
    console.print("update domain hosts [yellow]{}[/yellow] ......".format(domain))
    dns_rewrite_update(hosts, domain, dns_query_all(domain, all_save))
    console.print("update domain hosts [yellow]{}[/yellow] finished".format(domain))


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
            "support.github.com",
            "githubstatus.com",
            "polyfill.io",
            "google-analytics.com",
            "cloudfront.net",
            "gstatic.com",
            "fonts.gstatic.com",
            "github.githubassets.com",
            "camo.githubusercontent.com",
            "github.map.fastly.net",
            "github.global.ssl.fastly.net",
            "raw.githubusercontent.com",
            "user-images.githubusercontent.com",
            "collector.githubapp.com",
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
            console.print("[red]can not find domains[/red]")
            return
    elif isinstance(domain_list, (list, tuple, set)):
        pass
    else:
        console.print("[red]invalid domain_list[/red]")

    domain_list = list(set(domain_list))

    console.print(
        "will check and update domains: [yellow]{}[/yellow] [y/N]".format(
            " ".join(domain_list)
        ),
        end=":",
    )

    if not y:
        y = input()
        if y.lower() != "y":
            return
    else:
        console.print()

    hosts = get_hosts(hosts_path)
    if hosts is None:
        return

    with ThreadPoolExecutor(max_workers=5) as t:
        all_task = [
            t.submit(update_domain, domain=domain, hosts=hosts, all_save=a)
            for domain in domain_list
        ]
        wait(all_task, return_when=ALL_COMPLETED)
        console.print("all domain update finish")

    hosts.write()

    table = Table(title="Hosts File", show_header=True, header_style="bold magenta")
    table.add_column("domain", justify="center", style="magenta")
    table.add_column("ip", justify="center", style="cyan")

    for entry in hosts.entries:
        if isinstance(entry.names, (tuple, set, list)) and len(entry.names) > 0:
            table.add_row(entry.names[0], entry.address)

    console.print(table)


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
