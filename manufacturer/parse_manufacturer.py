#!/usr/bin/env python

# manuf.py: Parser library for Wireshark's OUI database.
# Copyright (c) 2016 Michael Huang
#
# This library is free software. It is dual licensed under the
# terms of the GNU Lesser General Public License version 3.0
# (or any later version) and the Apache License version 2.0.
#
# For more information, see:
#
# <http://www.gnu.org/licenses/>
# <http://www.apache.org/licenses/>

import re
import sys

from collections      import namedtuple
try:
    from cStringIO    import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io       import StringIO

# Vendor tuple
vendor = namedtuple('Vendor', ['manuf', 'comment'])

class MacParser(object):
    def  __init__(self, manuf_name = "manuf"):
        """Class that contains a parser for Wireshark's OUI database.
        Optimized for quick lookup performance by reading the entire file into
        memory on initialization. Maps ranges of MAC addresses to manufacturers and
        comments (descriptions). Contains full support for netmasks and other
        strange things in the database.
        See https://www.wireshark.org/tools/oui-lookup.html
        Args:
            manuf_name (str): Location of the manuf database file. Defaults to
            "manuf" in the same directory.
        Raises:
            IOError: If manuf file could not be found.
        """
        self._manuf_name = manuf_name
        self.refresh()

    def refresh(self, manuf_name = None):
        """Refresh/reload manuf database. Call this if database has been updated.
        Args:
            manuf_name (str): Location of the manuf data base file. Defaults to
            "manuf" in the same directory.
        Raises:
            IOError: If manuf file could not be found.
        """
        if not manuf_name:
            manuf_name = self._manuf_name
        with open(manuf_name, 'r') as f:
            manuf_file = StringIO(f.read())
        self._masks = {}

        # Build mask -> result dict
        for line in manuf_file:
            com = line.split('#', 1)
            arr = com[0].split()

            if len(arr) < 1:
                continue

            parts = arr[0].split('/')
            mac_str = self._strip_mac(parts[0])
            mac_int = self._get_mac_int(mac_str)
            mask = self._bits_left(mac_str)

            # Specification includes mask
            if len(parts) > 1:
                mask_spec = 48 - int(parts[1])
                if mask_spec > mask:
                    mask = mask_spec

            if len(com) > 1:
                result = vendor(manuf = arr[1], comment = com[1].strip())
            else:
                result = vendor(manuf = arr[1], comment = None)

            self._masks[(mask,  mac_int >> mask)] = result

        manuf_file.close()
        return self._masks

    # Gets the integer representation of a stripped mac string
    def _get_mac_int(self, mac_str):
        try:
            # Fill in missing bits with zeroes
            return int(mac_str, 16) << self._bits_left(mac_str)
        except ValueError:
            raise ValueError("Could not parse MAC: "+str(mac_str))

    # Strips the MAC address of '-', ':', and '.' characters
    _strip_mac = lambda self, mac: self._pattern.sub("", mac)
    _pattern = re.compile("[-:\.]")

    # Gets the number of bits left in a mac string
    _bits_left = lambda self, mac_str: 48 - 4 * len(mac_str)




def search(table, mac, max = 1):
    """Search for multiple vendor tuples possibly matching a MAC address.
    Args:
        mac (str): MAC address in standard format.
        max (Optional[int]): Maximum results to return. Defaults to 1.
    Returns:
        List of vendor namedtuples containing (manuf, comment), with closest
        result first. May be empty if no results found.
    Raises:
        ValueError: If the MAC could not be parsed.
    """
    vendors = []
    if max <= 0:
        return vendors
    mac_str = strip_mac(mac)
    mac_int = get_mac_int(mac_str)

    # If the user only gave us X bits, check X bits. No partial matching!
    for mask in range(bits_left(mac_str), 48):
        result = table.get((mask, mac_int >> mask))
        if result:
            vendors.append(result)
            if len(vendors) >= max:
                break
    return vendors

def get_all(mac):
    """Get a vendor tuple containing (manuf, comment) from a MAC address.
    Args:
        mac (str): MAC address in standard format.
    Returns:
        vendor: Vendor namedtuple containing (manuf, comment). Either or
        both may be None if not found.
    Raises:
        ValueError: If the MAC could not be parsed.
    """
    vendors = search(mac)
    if len(vendors) == 0:
        return vendor(manuf = None, comment = None)
    return vendors[0]
def get_manuf(mac):
    """Returns manufacturer from a MAC address.
    Args:
        mac (str): MAC address in standard format.
    Returns:
        string: String containing manufacturer, or None if not found.
    Raises:
        ValueError: If the MAC could not be parsed.
    """
    return get_all(mac).manuf

def get_comment(mac):
    """Returns comment from a MAC address.
    Args:
        mac (str): MAC address in standard format.
    Returns:
        string: String containing comment, or None if not found.
    Raises:
        ValueError: If the MAC could not be parsed.
    """
    return get_all(mac).comment

# Gets the integer representation of a stripped mac string
def get_mac_int(mac_str):
    try:
        # Fill in missing bits with zeroes
        return int(mac_str, 16) << bits_left(mac_str)
    except ValueError:
        raise ValueError("Could not parse MAC: "+str(mac_str))

# Strips the MAC address of '-', ':', and '.' characters
strip_mac = lambda mac: pattern.sub("", mac)
pattern = re.compile("[-:\.]")

# Gets the number of bits left in a mac string
bits_left = lambda mac_str: 48 - 4 * len(mac_str)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("manuf.py: Parser utility for Wireshark's OUI database.")
        print("    Usage: manuf.py <mac-address> [<manuf-file-path>]")
        sys.exit(0)
    elif len(sys.argv) > 2:
        parser = MacParser(sys.argv[2])
    else:
        parser = MacParser()
    print(parser.get_all(sys.argv[1]))
    sys.exit(0)