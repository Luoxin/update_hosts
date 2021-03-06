import sys

from rich.progress import track

from utils import is_ipv4, is_ipv6, is_readable, valid_hostnames


class HostsException(Exception):
    """ Base exception class. All Hosts-specific exceptions should subclass
    this class.
    """

    pass


class UnableToWriteHosts(HostsException):
    """ Raised when a Hosts file cannot be written. """

    pass


class HostsEntryException(Exception):
    """ Base exception class. All HostsEntry-specific exceptions should
    subclass this class.
    """

    pass


class InvalidIPv4Address(HostsEntryException):
    """ Raised when a HostsEntry is defined as type 'ipv4' but with an
    invalid address.
    """

    pass


class InvalidIPv6Address(HostsEntryException):
    """ Raised when a HostsEntry is defined as type 'ipv6' but
    with an invalid address.
    """

    pass


class InvalidAddress(HostsEntryException):
    """ Raised when a HostsEntry is defined as type is invalid.
    """

    pass


class InvalidComment(HostsEntryException):
    """ Raised when a HostsEntry is defined as type 'comment' but with an
    invalid comment
    """

    pass


class HostsEntry(object):
    __slots__ = ["entry_type", "address", "comment", "names"]

    def __init__(self, entry_type=None, address=None, comment=None, names=None):
        if not entry_type or entry_type not in ("ipv4", "ipv6", "comment", "blank"):
            raise Exception("entry_type invalid or not specified")

        if entry_type == "comment" and not comment:
            raise Exception("entry_type comment supplied without value.")

        if entry_type == "ipv4":
            if not all((address, names)):
                raise Exception("Address and Name(s) must be specified.")
            if not is_ipv4(address):
                raise InvalidIPv4Address()

        if entry_type == "ipv6":
            if not all((address, names)):
                raise Exception("Address and Name(s) must be specified.")
            if not is_ipv6(address):
                raise InvalidIPv6Address()

        self.entry_type = entry_type
        self.address = address
        self.comment = comment
        self.names = names

    def is_real_entry(self):
        return self.entry_type in ("ipv4", "ipv6")

    def __repr__(self):
        return (
            "HostsEntry(entry_type='{0}', address='{1}', "
            "comment={2}, names={3})".format(
                self.entry_type, self.address, self.comment, self.names
            )
        )

    def __str__(self):
        if self.entry_type in ("ipv4", "ipv6"):
            return "TYPE={0}, ADDR={1}, NAMES={2}".format(
                self.entry_type, self.address, " ".join(self.names)
            )
        elif self.entry_type == "comment":
            return "TYPE = {0}, COMMENT = {1}".format(self.entry_type, self.comment)
        elif self.entry_type == "blank":
            return "TYPE = {0}".format(self.entry_type)

    @staticmethod
    def get_entry_type(hosts_entry=None):
        if hosts_entry and isinstance(hosts_entry, str):
            entry = hosts_entry.strip()
            if not entry or not entry[0] or entry[0] == "\n":
                return "blank"
            if entry[0] == "#":
                return "comment"
            entry_chunks = entry.split()
            if is_ipv6(entry_chunks[0]):
                return "ipv6"
            if is_ipv4(entry_chunks[0]):
                return "ipv4"

    @staticmethod
    def str_to_hostentry(entry):
        line_parts = entry.strip().split()
        if is_ipv4(line_parts[0]) and valid_hostnames(line_parts[1:]):
            return HostsEntry(
                entry_type="ipv4", address=line_parts[0], names=line_parts[1:]
            )
        elif is_ipv6(line_parts[0]) and valid_hostnames(line_parts[1:]):
            return HostsEntry(
                entry_type="ipv6", address=line_parts[0], names=line_parts[1:]
            )
        else:
            return False


class Hosts(object):
    __slots__ = ["entries", "hosts_path"]

    def __init__(self, path=None):
        self.entries = []
        if path:
            self.hosts_path = path
        else:
            self.hosts_path = self.determine_hosts_path()
        self.populate_entries()

    def __repr__(self):
        return "Hosts(hosts_path='{0}', entries={1})".format(
            self.hosts_path, self.entries
        )

    def __str__(self):
        output = "hosts_path={0}, ".format(self.hosts_path)
        for entry in self.entries:
            output += str(entry)
        return output

    def count(self):
        return len(self.entries)

    @staticmethod
    def determine_hosts_path(platform=None):
        if platform:
            pass
        elif sys.platform.startswith("win"):
            platform = "C:\WINDOWS\system32\drivers\etc\hosts"
        elif sys.platform.startswith("linux"):
            platform = "/etc/hosts "
        elif sys.platform.startswith("darwin"):
            platform = "/ect/hosts"
        elif sys.platform == "cygwin":
            platform = "C:\WINDOWS\system32\drivers\etc\hosts"
        elif sys.platform == "aix":
            platform = "/ect/hosts"
        else:
            platform = "/ect/hosts"

        return platform

    def write(self, path=None):
        if path:
            output_file_path = path
        else:
            output_file_path = self.hosts_path
        try:
            with open(output_file_path, "w") as hosts_file:
                for line in track(
                    self.entries,
                    description="write into hosts file {}".format(self.hosts_path),
                ):
                    if line.entry_type == "comment":
                        hosts_file.write(line.comment + "\n")
                    elif line.entry_type == "blank":
                        hosts_file.write("\n")
                    elif line.entry_type == "ipv4":
                        hosts_file.write(
                            "{0}\t{1}\n".format(line.address, " ".join(line.names),)
                        )
                    elif line.entry_type == "ipv6":
                        hosts_file.write(
                            "{0}\t{1}\n".format(line.address, " ".join(line.names),)
                        )
        except:
            raise UnableToWriteHosts()

    def exists(self, address=None, names=None, comment=None):
        for entry in self.entries:
            if entry.entry_type in ("ipv4", "ipv6"):
                if address and address == entry.address:
                    return True
                if names:
                    for name in names:
                        if name in entry.names:
                            return True
            elif entry.entry_type == "comment" and entry.comment == comment:
                return True
        return False

    def remove_all_matching(self, address=None, name=None):
        if self.entries:
            if address and name:
                func = lambda entry: not entry.is_real_entry() or (
                    entry.address != address and name not in entry.names
                )
            elif address:
                func = (
                    lambda entry: not entry.is_real_entry() or entry.address != address
                )
            elif name:
                func = (
                    lambda entry: not entry.is_real_entry() or name not in entry.names
                )
            else:
                raise ValueError("No address or name was specified for removal.")
            self.entries = list(filter(func, self.entries))

    def import_url(self, url=None, force=None):
        file_contents = self.get_hosts_by_url(url=url).decode("utf-8")
        file_contents = file_contents.rstrip().replace("^M", "\n")
        file_contents = file_contents.rstrip().replace("\r\n", "\n")
        lines = file_contents.split("\n")
        skipped = 0
        import_entries = []
        for line in lines:
            stripped_entry = line.strip()
            if (not stripped_entry) or (stripped_entry.startswith("#")):
                skipped += 1
            else:
                line = line.partition("#")[0]
                line = line.rstrip()
                import_entry = HostsEntry.str_to_hostentry(line)
                if import_entry:
                    import_entries.append(import_entry)
        add_result = self.add(entries=import_entries, force=force)
        write_result = self.write()
        return {
            "result": "success",
            "skipped": skipped,
            "add_result": add_result,
            "write_result": write_result,
        }

    def import_file(self, import_file_path=None):
        skipped = 0
        invalid_count = 0
        if is_readable(import_file_path):
            import_entries = []
            with open(import_file_path, "r") as infile:
                for line in infile:
                    stripped_entry = line.strip()
                    if (not stripped_entry) or (stripped_entry.startswith("#")):
                        skipped += 1
                    else:
                        line = line.partition("#")[0]
                        line = line.rstrip()
                        import_entry = HostsEntry.str_to_hostentry(line)
                        if import_entry:
                            import_entries.append(import_entry)
                        else:
                            invalid_count += 1
            add_result = self.add(entries=import_entries)
            write_result = self.write()
            return {
                "result": "success",
                "skipped": skipped,
                "invalid_count": invalid_count,
                "add_result": add_result,
                "write_result": write_result,
            }
        else:
            return {
                "result": "failed",
                "message": "Cannot read: file {0}.".format(import_file_path),
            }

    def add(
        self, entries: (list, set, tuple) = None,
    ):
        for item in entries:
            if item.entry_type == "comment":
                self.entries.append(item)
            elif item.entry_type == "ipv4":
                self.entries.append(item)
            elif item.entry_type == "ipv6":
                self.entries.append(item)
            else:
                raise InvalidAddress()

    def populate_entries(self):
        try:
            with open(self.hosts_path, "r") as hosts_file:
                hosts_entries = [line for line in hosts_file]
                for hosts_entry in hosts_entries:
                    entry_type = HostsEntry.get_entry_type(hosts_entry)
                    if entry_type == "comment":
                        hosts_entry = hosts_entry.replace("\r", "")
                        hosts_entry = hosts_entry.replace("\n", "")
                        self.entries.append(
                            HostsEntry(entry_type="comment", comment=hosts_entry)
                        )
                    elif entry_type == "blank":
                        self.entries.append(HostsEntry(entry_type="blank"))
                    elif entry_type in ("ipv4", "ipv6"):
                        chunked_entry = hosts_entry.split()
                        stripped_name_list = [
                            name.strip() for name in chunked_entry[1:]
                        ]

                        self.entries.append(
                            HostsEntry(
                                entry_type=entry_type,
                                address=chunked_entry[0].strip(),
                                names=stripped_name_list,
                            )
                        )
        except IOError:
            raise Exception("failed, cannot read {}".format(self.hosts_path))
