"""Longest-prefix-match radix trie over IP-address bits (IPv4 and IPv6).

A shared primitive for enrichers that map CIDRs to values: the asset zone map
(:mod:`ulpf.enrich.network_context`) and the CIDR indicator set
(:mod:`ulpf.enrich.threat_intel`).

:class:`CidrTrie` keeps one binary trie per address family. ``insert`` walks the
first ``prefixlen`` bits of the network address; ``lookup`` walks the query
address bit by bit and returns the value at the **deepest** prefix that matched
(so ``10.1.2.7/32`` wins over a covering ``10.0.0.0/8``). Lookup is
O(address-width), independent of how many prefixes are stored.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from typing import Generic, TypeVar

_T = TypeVar("_T")

_V4_BITS = 32
_V6_BITS = 128


class _Node(Generic[_T]):
    """One bit position: two children and an optional value for a prefix ending here."""

    __slots__ = ("children", "value")

    def __init__(self) -> None:
        self.children: list[_Node[_T] | None] = [None, None]
        self.value: _T | None = None


class _Trie(Generic[_T]):
    """Fixed-width binary trie for a single address family."""

    __slots__ = ("_root", "_bits")

    def __init__(self, bits: int) -> None:
        self._root: _Node[_T] = _Node()
        self._bits = bits

    def insert(self, key: int, prefix_len: int, value: _T) -> None:
        """Store ``value`` at the ``prefix_len``-bit prefix of ``key``."""
        node = self._root
        for i in range(prefix_len):
            bit = (key >> (self._bits - 1 - i)) & 1
            child = node.children[bit]
            if child is None:
                child = _Node()
                node.children[bit] = child
            node = child
        node.value = value

    def search(self, key: int) -> _T | None:
        """Return the value at the longest stored prefix of ``key``, or ``None``."""
        node: _Node[_T] | None = self._root
        best = self._root.value
        for i in range(self._bits):
            assert node is not None
            node = node.children[(key >> (self._bits - 1 - i)) & 1]
            if node is None:
                break
            if node.value is not None:
                best = node.value
        return best


class CidrTrie(Generic[_T]):
    """CIDR -> value index with longest-prefix lookup, one trie per address family."""

    def __init__(self, entries: Iterable[tuple[IPv4Network | IPv6Network, _T]] = ()) -> None:
        """Build from ``(network, value)`` pairs."""
        self._v4: _Trie[_T] = _Trie(_V4_BITS)
        self._v6: _Trie[_T] = _Trie(_V6_BITS)
        self._count = 0
        for network, value in entries:
            self.insert(network, value)

    def insert(self, network: IPv4Network | IPv6Network, value: _T) -> None:
        """Add one CIDR -> value mapping."""
        trie = self._v4 if network.version == 4 else self._v6
        trie.insert(int(network.network_address), network.prefixlen, value)
        self._count += 1

    def __len__(self) -> int:
        """Number of CIDR entries inserted."""
        return self._count

    def lookup(self, ip: str | IPv4Address | IPv6Address) -> _T | None:
        """Return the value for the most specific CIDR containing ``ip``, or ``None``."""
        obj = ip if isinstance(ip, (IPv4Address, IPv6Address)) else ip_address(str(ip))
        trie = self._v4 if obj.version == 4 else self._v6
        return trie.search(int(obj))
