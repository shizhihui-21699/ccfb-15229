package com.example.links;

import java.util.ArrayList;
import java.util.List;

/**
 * Matches the direct TCP peer's IP address against a configured set of trusted
 * proxy CIDR ranges (IPv4 and IPv6). Only requests arriving from a trusted proxy
 * may use {@code X-Forwarded-*} headers — and even then, only to <em>select</em>
 * a whitelisted site, never to introduce a new host.
 */
public final class TrustedProxyMatcher {

    private final List<byte[]> networks = new ArrayList<>();
    private final List<Integer> prefixBits = new ArrayList<>();

    private TrustedProxyMatcher() {
    }

    public static TrustedProxyMatcher of(List<String> cidrs) {
        TrustedProxyMatcher m = new TrustedProxyMatcher();
        for (String cidr : cidrs) {
            m.add(cidr);
        }
        return m;
    }

    /** An empty matcher trusts nobody — the safe default. */
    public static TrustedProxyMatcher none() {
        return new TrustedProxyMatcher();
    }

    private void add(String cidr) {
        String ip = cidr;
        int bits = -1;
        int slash = cidr.indexOf('/');
        if (slash >= 0) {
            ip = cidr.substring(0, slash);
            bits = Integer.parseInt(cidr.substring(slash + 1));
        }
        byte[] addr = parseIp(ip);
        if (addr == null) {
            throw new IllegalArgumentException("Not an IP address in CIDR: " + cidr);
        }
        if (bits < 0) {
            bits = addr.length * 8;
        }
        if (bits > addr.length * 8) {
            throw new IllegalArgumentException("Prefix too long in CIDR: " + cidr);
        }
        networks.add(addr);
        prefixBits.add(bits);
    }

    public boolean matches(String ip) {
        if (ip == null) {
            return false;
        }
        byte[] addr = parseIp(ip.trim());
        if (addr == null) {
            return false;
        }
        for (int i = 0; i < networks.size(); i++) {
            byte[] net = networks.get(i);
            if (net.length != addr.length) {
                continue;
            }
            if (prefixMatches(net, addr, prefixBits.get(i))) {
                return true;
            }
        }
        return false;
    }

    private static boolean prefixMatches(byte[] network, byte[] addr, int bits) {
        int fullBytes = bits / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (network[i] != addr[i]) {
                return false;
            }
        }
        int rem = bits % 8;
        if (rem == 0) {
            return true;
        }
        int mask = 0xFF << (8 - rem);
        return (network[fullBytes] & mask) == (addr[fullBytes] & mask);
    }

    /** Returns the address as 4 (IPv4) or 16 (IPv6) bytes, or {@code null} if invalid. */
    static byte[] parseIp(String ip) {
        if (ip.indexOf(':') >= 0) {
            return parseIpv6(ip);
        }
        return parseIpv4(ip);
    }

    private static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || (p.length() > 1 && p.startsWith("0"))) {
                return null;
            }
            for (char c : p.toCharArray()) {
                if (c < '0' || c > '9') {
                    return null;
                }
            }
            int v = Integer.parseInt(p);
            if (v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    private static byte[] parseIpv6(String ip) {
        // Handle IPv4-embedded tail, e.g. "::ffff:192.0.2.1"
        byte[] v4Tail = null;
        int lastColon = ip.lastIndexOf(':');
        if (lastColon >= 0 && ip.substring(lastColon + 1).indexOf('.') >= 0) {
            v4Tail = parseIpv4(ip.substring(lastColon + 1));
            if (v4Tail == null) {
                return null;
            }
            ip = ip.substring(0, lastColon);
        }

        String head = ip;
        String tail = "";
        int dc = ip.indexOf("::");
        if (dc >= 0) {
            if (ip.indexOf("::", dc + 2) >= 0) {
                return null; // more than one "::"
            }
            head = ip.substring(0, dc);
            tail = ip.substring(dc + 2);
        }

        List<Integer> headGroups = parseGroups(head);
        List<Integer> tailGroups = parseGroups(tail);
        if (headGroups == null || tailGroups == null) {
            return null;
        }
        int groupCount = headGroups.size() + tailGroups.size() + (v4Tail != null ? 2 : 0);
        if (dc >= 0) {
            if (groupCount >= 8) {
                return null; // "::" must compress at least one group
            }
        } else if (groupCount != 8) {
            return null;
        }

        List<Integer> groups = new ArrayList<>(headGroups);
        if (dc >= 0) {
            int zeros = 8 - groupCount;
            for (int i = 0; i < zeros; i++) {
                groups.add(0);
            }
        }
        groups.addAll(tailGroups);

        byte[] out = new byte[16];
        for (int i = 0; i < groups.size(); i++) {
            out[i * 2] = (byte) (groups.get(i) >> 8);
            out[i * 2 + 1] = (byte) (int) groups.get(i);
        }
        if (v4Tail != null) {
            System.arraycopy(v4Tail, 0, out, 12, 4);
        }
        return out;
    }

    private static List<Integer> parseGroups(String s) {
        List<Integer> groups = new ArrayList<>();
        if (s.isEmpty()) {
            return groups;
        }
        for (String g : s.split(":", -1)) {
            if (g.isEmpty() || g.length() > 4) {
                return null;
            }
            try {
                groups.add(Integer.parseInt(g, 16));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return groups;
    }
}
