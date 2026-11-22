package com.example.links;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HostNormalizerTest {

    @Test
    void plainHostPassesThrough() {
        assertEquals("example.com", HostNormalizer.normalize("example.com"));
    }

    @Test
    void caseAndTrailingDotAreNormalized() {
        assertEquals("example.com", HostNormalizer.normalize("EXAMPLE.com."));
        assertEquals("www.example.com", HostNormalizer.normalize("  WWW.Example.COM  "));
    }

    @Test
    void numericPortIsStripped() {
        assertEquals("example.com", HostNormalizer.normalize("example.com:443"));
        assertEquals("example.com", HostNormalizer.normalize("example.com:8443"));
    }

    @Test
    void unicodeIsConvertedToPunycode() {
        assertEquals("xn--bcher-kva.example", HostNormalizer.normalize("bücher.example"));
        // already-punycode stays as-is
        assertEquals("xn--bcher-kva.example", HostNormalizer.normalize("xn--bcher-kva.example"));
    }

    @Test
    void userinfoTrickIsRejected() {
        // "legit.com:443@evil.com" would parse as host=evil.com in a naive URL parser
        assertNull(HostNormalizer.normalize("legit.com:443@evil.com"));
        assertNull(HostNormalizer.normalize("evil.com@legit.com"));
    }

    @Test
    void pathsBackslashesAndWhitespaceAreRejected() {
        assertNull(HostNormalizer.normalize("evil.com/legit.com"));
        assertNull(HostNormalizer.normalize("evil.com\\@legit.com"));
        assertNull(HostNormalizer.normalize("evil .com"));
        assertNull(HostNormalizer.normalize("evil\t.com"));
    }

    @Test
    void malformedPortsAreRejected() {
        assertNull(HostNormalizer.normalize("example.com:"));
        assertNull(HostNormalizer.normalize("example.com:abc"));
        assertNull(HostNormalizer.normalize("example.com:999999"));
    }

    @Test
    void bareIpv6WithoutBracketsIsRejected() {
        assertNull(HostNormalizer.normalize("::1"));
        assertNull(HostNormalizer.normalize("2001:db8::1"));
    }

    @Test
    void bracketedIpv6LiteralIsAccepted() {
        assertEquals("::1", HostNormalizer.normalize("[::1]"));
        assertEquals("2001:db8::1", HostNormalizer.normalize("[2001:db8::1]:8443"));
    }

    @Test
    void nullAndEmptyAreRejected() {
        assertNull(HostNormalizer.normalize(null));
        assertNull(HostNormalizer.normalize(""));
        assertNull(HostNormalizer.normalize("   "));
        assertNull(HostNormalizer.normalize("..."));
    }
}
