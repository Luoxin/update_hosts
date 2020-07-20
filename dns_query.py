from multiprocessing import Pipe

import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.nsbase
import dns.resolver
import requests
import simplejson
from cacheout import Cache

from console import console
from dns_list import dns_service_list
from lock import new_lock, acquire
from utils import is_ipv4, is_ipv6, is_internal_ip


class DnsQueryBaseException(Exception):
    """net work base exception"""


class DnsQuery(object):
    def __init__(self, dns_service: (list, tuple, set) = None):

        self._cache = Cache()
        self._query_cache = set()
        self.recv, self.send = Pipe(duplex=True)
        self._lock = new_lock()

        if dns_service is None or len(dns_service) == 0:
            dns_service = dns_service_list

        self.dns_service = dns_service

    @staticmethod
    def _gen_key(dns_server: str, domain: str) -> str:
        return "{}_{}".format(domain, dns_server)

    def query(self, dns_server: str, domain: str) -> (list, list):
        key = self._gen_key(dns_server=dns_server, domain=domain)

        console.print(
            "dns query [yellow]{}[/yellow]([purple]{}[/purple])".format(
                domain, dns_server
            )
        )

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

                a = resolver.query(domain, lifetime=5, rdtype=dns.rdatatype.A)

                for i in a.response.answer:
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

        for ip in ip_list:
            if is_internal_ip(ip):
                ip_list.remove(ip)

        self._cache.set(key=key, value=(ip_list, cname_list))

        return ip_list, cname_list

    def work(self):
        while True:
            data = self.recv.recv()
            if isinstance(data, (tuple, list, set)):
                ip_list, cname_list = self.query(data[0], data[1])

                for cname in cname_list:
                    self.add(cname)

            elif isinstance(data, bool):
                break

        # CLOSE

    def add(self, domain: str):
        def add(server: str):
            key = self._gen_key(dns_server=server, domain=domain)

            with acquire(self._lock):
                if key not in self._query_cache:
                    self._query_cache.add(key)
                    self.send.send([server, domain])

        for dns_server in self.dns_service:
            add(dns_server)

    def close(self):
        self.send.send(True)
