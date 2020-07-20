import sys
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait, ALL_COMPLETED
from enum import Enum, unique
import json
import os
from concurrent.futures.thread import ThreadPoolExecutor
from multiprocessing import Pipe
from urllib.parse import urlparse
from concurrent.futures import wait, ALL_COMPLETED
import requests
from faker import Faker
from requests.adapters import HTTPAdapter
from rich.console import Console
from urllib3 import Retry
from you_get.extractors import Bilibili
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.nsbase
import dns.resolver
import fire
import requests
import simplejson
from cacheout import Cache
from faker import Faker
from ping3 import ping
from rich.console import Console
from rich.progress import track
from rich.table import Table

from console import console
from dns_list import dns_service_list
from hosts import Hosts, HostsEntry
from lock import new_lock, acquire
from utils import is_ipv4, is_ipv6, is_internal_ip


@unique
class CheckType(Enum):
    Ping = 1
    HttpDelayed = 2
    HttpSpeed = 3


class CheckConnectivity(object):
    def __init__(self):
        self._cache = Cache()
        self._query_cache = set()
        self._lock = new_lock()

        self.check_type = CheckType.Ping

    def set_check_type(self, t: CheckType):
        self.check_type = t

    def check(self, ip):
        console.print(
            "check connectivity [yellow]{}[/yellow] with".format(
                ip
            ), end=" "
        )

        if self.check_type == CheckType.Ping:
            try:
                if is_ipv4(ip) or is_ipv6(ip):
                    pass
                else:
                    console.print("{} type is err".format(ip))

                delay = ping(ip, unit="ms", timeout=5)
                self._cache.set(ip, delay)
            except OSError:
                self._cache.set(ip, -1)
            except:
                console.print_exception()
                self._cache.set(ip, -1)
        elif (
            self.check_type == CheckType.HttpDelayed
            or self.check_type == CheckType.HttpSpeed
        ):
            try:
                start_time = time.time()
                r = requests.get(
                    url="http://{}".format(ip),
                    timeout=60,
                    headers={"Connection": "close", "User-Agent": f.user_agent()},
                )
                request_time = time.time() - start_time
                del start_time
                size = sys.getsizeof(r.content) / 1024
                network_delay = r.elapsed.microseconds / 1000 / 1000
                speed = size / (request_time - network_delay)
                r.close()
                del r

                if self.check_type == CheckType.HttpDelayed:
                    self._cache.set(ip, network_delay)
                elif self.check_type == CheckType.HttpSpeed:
                    self._cache.set(ip, speed)

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                self._cache.set(ip, -1)
            except:
                console.print_exception()
                self._cache.set(ip, -1)
        else:
            console.print("invalid type", style="red")
            self._cache.set(ip, -1)