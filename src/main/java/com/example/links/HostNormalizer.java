package com.example.links;

import java.net.IDN;
import java.util.Locale;

/**
 * Normalizes a raw {@code Host} / {@code X-Forwarded-Host} value into a canonical
 * form that can be compared against the configured site whitelist.
 *
 * <p>Returns {@code null} for anything malformed or suspicious — callers must treat
 * {@code null} as "no match" and fall back to the default site. The request can never
 * fail closed to an attacker-controlled value, because the output of this class is only
 * ever used as a <em>lookup key</em> into server-side configuration.</p>
 */
final class HostNormalizer {

    private HostNormalizer() {
    }

    /**
     * Normalizes a host[:port] value to lowercase punycode without the port.
     *
     * <ul>
     *   <li>rejects userinfo tricks ({@code legit.com@evil.com}), paths, backslashes</li>
     *   <li>strips a single {@code :port} suffix (numeric, 1-5 digits)</li>
     *   <li>handles bracketed IPv6 literals ({@code [::1]:8080})</li>
     *   <li>strips trailing dots (FQDN form {@code example.com.})</li>
     *   <li>lowercases and converts IDN labels to punycode (A-labels)</li>
     * </ul>
     */
    static String normalize(String rawHost) {
        if (rawHost == null) {
            return null;
        }
        String h = rawHost.trim();
        if (h.isEmpty()) {
            return null;
        }
        // A Host value never legitimately contains userinfo, a path, or a backslash.
        // Reject outright instead of trying to "parse around" them.
        if (h.indexOf('@') >= 0 || h.indexOf('/') >= 0 || h.indexOf('\\') >= 0) {
            return null;
        }
        if (h.chars().anyMatch(Character::isWhitespace)) {
            return null;
        }

        if (h.startsWith("[")) {
            // Bracketed IPv6 literal, optionally with :port
            int end = h.indexOf(']');
            if (end < 0) {
                return null;
            }
            String rest = h.substring(end + 1);
            if (!rest.isEmpty() && !rest.matches(":\\d{1,5}")) {
                return null;
            }
            return h.substring(1, end).toLowerCase(Locale.ROOT);
        }

        int colon = h.indexOf(':');
        if (colon >= 0) {
            // A second colon means a bare IPv6 literal — not valid in a Host header
            // without brackets, and never something we put into an outbound link.
            if (h.indexOf(':', colon + 1) >= 0) {
                return null;
            }
            String port = h.substring(colon + 1);
            if (!port.matches("\\d{1,5}")) {
                return null;
            }
            h = h.substring(0, colon);
        }

        // Strip trailing dots: "example.com." is the FQDN form of "example.com".
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.isEmpty()) {
            return null;
        }

        String lower = h.toLowerCase(Locale.ROOT);
        try {
            // Canonical punycode so "bücher.example" and "xn--bcher-kva.example"
            // compare equal, and confusable Unicode never matches an ASCII whitelist
            // entry by accident.
            return IDN.toASCII(lower, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
