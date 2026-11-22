package com.example.links;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedProxyMatcherTest {

    @Test
    void ipv4Cidr() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("10.0.0.0/8"));
        assertTrue(m.matches("10.1.2.3"));
        assertTrue(m.matches("10.255.255.255"));
        assertFalse(m.matches("11.0.0.1"));
        assertFalse(m.matches("203.0.113.9"));
    }

    @Test
    void ipv4ExactHost() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("192.168.1.10/32", "172.16.0.1"));
        assertTrue(m.matches("192.168.1.10"));
        assertTrue(m.matches("172.16.0.1"));
        assertFalse(m.matches("192.168.1.11"));
    }

    @Test
    void ipv4BoundaryBits() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("10.0.0.0/9"));
        assertTrue(m.matches("10.127.255.255"));
        assertFalse(m.matches("10.128.0.0"));
    }

    @Test
    void ipv6Cidr() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("2001:db8::/32"));
        assertTrue(m.matches("2001:db8::1"));
        assertTrue(m.matches("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
        assertFalse(m.matches("2001:db9::1"));
        assertFalse(m.matches("::1"));
    }

    @Test
    void ipv6CompressedAndMappedForms() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("::ffff:10.0.0.0/104"));
        assertTrue(m.matches("::ffff:10.1.2.3"));
        assertFalse(m.matches("::ffff:11.0.0.1"));
    }

    @Test
    void ipv4NeverMatchesIpv6RangeAndViceVersa() {
        TrustedProxyMatcher v4 = TrustedProxyMatcher.of(List.of("10.0.0.0/8"));
        assertFalse(v4.matches("::ffff:10.1.2.3")); // different address family, no silent match
        TrustedProxyMatcher v6 = TrustedProxyMatcher.of(List.of("::/0"));
        assertFalse(v6.matches("10.1.2.3"));
    }

    @Test
    void emptyMatcherTrustsNobody() {
        assertFalse(TrustedProxyMatcher.none().matches("10.1.2.3"));
        assertFalse(TrustedProxyMatcher.none().matches(null));
    }

    @Test
    void garbageInputDoesNotMatch() {
        TrustedProxyMatcher m = TrustedProxyMatcher.of(List.of("10.0.0.0/8"));
        assertFalse(m.matches("not-an-ip"));
        assertFalse(m.matches("10.1.2.256"));
        assertFalse(m.matches("10.1.2.03"));   // leading zero rejected, no octet ambiguity
        assertFalse(m.matches(""));
        assertFalse(m.matches(null));
    }

    @Test
    void invalidCidrIsRejectedAtConfigTime() {
        assertThrows(IllegalArgumentException.class, () -> TrustedProxyMatcher.of(List.of("999.0.0.0/8")));
        assertThrows(IllegalArgumentException.class, () -> TrustedProxyMatcher.of(List.of("10.0.0.0/33")));
        assertThrows(IllegalArgumentException.class, () -> TrustedProxyMatcher.of(List.of("example.com/8")));
    }
}
