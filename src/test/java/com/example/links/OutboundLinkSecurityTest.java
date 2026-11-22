package com.example.links;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Security regression tests: every known Host-header / forwarded-header tampering
 * technique must produce a link on one of our own configured origins.
 *
 * <p>Topology under test (multi-domain, multi-locale, multi-level proxy):</p>
 * <ul>
 *   <li>main:    example.com (+ www alias), locales zh (default), en, ja</li>
 *   <li>eu:      example.eu, locales en (default), de, fr</li>
 *   <li>admin:   admin.example.com, exposed by the outer proxy under /console</li>
 *   <li>idn:     bücher.example (punycode xn--bcher-kva.example)</li>
 *   <li>staging: staging.internal.example on non-standard port 8443</li>
 *   <li>trusted proxies: 10.0.0.0/8 and 2001:db8::/32</li>
 * </ul>
 */
class OutboundLinkSecurityTest {

    private static final PublicUrlConfig CONFIG = PublicUrlConfig.builder()
            .site(Site.builder("main")
                    .host("example.com").host("www.example.com")
                    .defaultLocale("zh").supportedLocale("en").supportedLocale("ja")
                    .build())
            .site(Site.builder("eu")
                    .host("example.eu")
                    .defaultLocale("en").supportedLocale("de").supportedLocale("fr")
                    .build())
            .site(Site.builder("admin")
                    .host("admin.example.com")
                    .defaultLocale("zh")
                    .basePath("/console")
                    .build())
            .site(Site.builder("idn")
                    .host("bücher.example")
                    .defaultLocale("de")
                    .build())
            .site(Site.builder("staging")
                    .host("staging.internal.example")
                    .defaultLocale("zh")
                    .port(8443)
                    .build())
            .defaultSite("main")
            .trustedProxies(List.of("10.0.0.0/8", "2001:db8::/32"))
            .httpsOnly(false)
            .build();

    private final OutboundLinkService links = new OutboundLinkService(CONFIG);

    private String resetLink(RequestView req) {
        return links.passwordResetLink(req, "zh", "tok123");
    }

    // ---------------------------------------------------------------- baseline

    @Test
    void baselineBehindTrustedProxy() {
        String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "example.com"));
        assertEquals("https://example.com/auth/reset-password?token=tok123", link);
    }

    @Test
    void allFourLinkTypesGoThroughTheSamePolicy() {
        RequestView evil = TestRequest.viaTrustedProxy().header("Host", "evil.example");
        assertTrue(links.passwordResetLink(evil, "zh", "t").startsWith("https://example.com/"));
        assertTrue(links.emailVerificationLink(evil, "zh", "t").startsWith("https://example.com/"));
        assertTrue(links.invitationLink(evil, "zh", "i1").startsWith("https://example.com/"));
        assertTrue(links.shareLink(evil, "zh", "doc", "42").startsWith("https://example.com/"));
    }

    // ------------------------------------------------------- Host header attacks

    @Nested
    class HostHeaderTampering {

        @Test
        void attackerDomainIsIgnored() {
            assertEquals("https://example.com/auth/reset-password?token=tok123",
                    resetLink(TestRequest.viaTrustedProxy().header("Host", "attacker.example")));
        }

        @Test
        void suffixLookalikeIsIgnored() {
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "example.com.attacker.example"));
            assertTrue(link.startsWith("https://example.com/"));
        }

        @Test
        void userinfoTrickIsRejected() {
            // Naive URL parsing reads "example.eu:443@attacker.example" as host=attacker.example
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "example.eu:443@attacker.example"));
            assertTrue(link.startsWith("https://example.com/"));
            assertFalse(link.contains("attacker"));
        }

        @Test
        void pathAndBackslashTricksAreRejected() {
            assertTrue(resetLink(TestRequest.viaTrustedProxy()
                    .header("Host", "attacker.example/\\.@example.eu")).startsWith("https://example.com/"));
        }

        @Test
        void portInjectionDoesNotChangeOrigin() {
            assertEquals("https://example.eu/auth/reset-password?token=tok123",
                    resetLink(TestRequest.viaTrustedProxy().header("Host", "example.eu:443")));
            // a weird port on an unknown host still falls back to the default site
            assertTrue(resetLink(TestRequest.viaTrustedProxy()
                    .header("Host", "attacker.example:1337")).startsWith("https://example.com/"));
        }

        @Test
        void caseAndTrailingDotStillMatchLegitSite() {
            assertEquals("https://example.eu/auth/reset-password?token=tok123",
                    resetLink(TestRequest.viaTrustedProxy().header("Host", "  EXAMPLE.eu.  ")));
        }

        @Test
        void unicodeLookalikeDoesNotMatchAsciiSite() {
            // Cyrillic 'е' (U+0435) — visually identical to "example.com"
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "еxample.com"));
            assertTrue(link.startsWith("https://example.com/"));
            assertFalse(link.contains("xn--"));
        }

        @Test
        void missingHostFallsBackToDefaultSite() {
            assertTrue(resetLink(TestRequest.viaTrustedProxy()).startsWith("https://example.com/"));
        }
    }

    // ------------------------------------------------- X-Forwarded-* handling

    @Nested
    class ForwardedHeaders {

        @Test
        void forwardedHostSelectsConfiguredSiteBehindTrustedProxy() {
            RequestView req = TestRequest.viaTrustedProxy()
                    .header("Host", "internal-lb.local")
                    .header("X-Forwarded-Host", "example.eu");
            assertEquals("https://example.eu/auth/reset-password?token=tok123", resetLink(req));
        }

        @Test
        void forwardedHostFromUntrustedClientIsIgnored() {
            RequestView req = TestRequest.direct()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Host", "attacker.example");
            assertEquals("https://example.com/auth/reset-password?token=tok123", resetLink(req));
        }

        @Test
        void attackerForwardedHostBehindTrustedProxyFallsBackToDefault() {
            RequestView req = TestRequest.viaTrustedProxy()
                    .header("Host", "example.eu")
                    .header("X-Forwarded-Host", "attacker.example");
            assertTrue(resetLink(req).startsWith("https://example.com/"));
        }

        @Test
        void commaJoinedForwardedHostUsesFirstValueAsWhitelistKey() {
            RequestView legit = TestRequest.viaTrustedProxy()
                    .header("X-Forwarded-Host", "example.eu, internal-proxy.local");
            assertEquals("https://example.eu/auth/reset-password?token=tok123", resetLink(legit));

            RequestView smuggled = TestRequest.viaTrustedProxy()
                    .header("X-Forwarded-Host", "attacker.example, example.eu");
            assertTrue(resetLink(smuggled).startsWith("https://example.com/"));
        }

        @Test
        void emptyForwardedHostFallsBackToHostHeader() {
            RequestView req = TestRequest.viaTrustedProxy()
                    .header("X-Forwarded-Host", "")
                    .header("Host", "example.eu");
            assertEquals("https://example.eu/auth/reset-password?token=tok123", resetLink(req));
        }

        @Test
        void forwardedProtoMustBeHttpOrHttps() {
            RequestView js = TestRequest.viaTrustedProxy()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Proto", "javascript:alert(1)");
            assertTrue(resetLink(js).startsWith("https://"));

            RequestView garbage = TestRequest.viaTrustedProxy()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Proto", "gopher");
            assertTrue(resetLink(garbage).startsWith("https://"));
        }

        @Test
        void forwardedProtoHonoredOnlyFromTrustedProxy() {
            RequestView trusted = TestRequest.viaTrustedProxy()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Proto", "http");
            assertTrue(resetLink(trusted).startsWith("http://example.com/"));

            RequestView untrusted = TestRequest.direct()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Proto", "http");
            assertTrue(resetLink(untrusted).startsWith("https://"));
        }

        @Test
        void httpsOnlyConfigIgnoresForwardedProtoEntirely() {
            PublicUrlConfig strict = PublicUrlConfig.builder()
                    .site(Site.builder("main").host("example.com").defaultLocale("zh").build())
                    .trustedProxies(List.of("10.0.0.0/8"))
                    .httpsOnly(true)
                    .build();
            OutboundLinkService strictLinks = new OutboundLinkService(strict);
            RequestView req = TestRequest.viaTrustedProxy()
                    .header("Host", "example.com")
                    .header("X-Forwarded-Proto", "http");
            assertTrue(strictLinks.passwordResetLink(req, "zh", "t").startsWith("https://"));
        }

        @Test
        void ipv6TrustedProxyIsRecognized() {
            RequestView req = TestRequest.from("2001:db8::5")
                    .header("X-Forwarded-Host", "example.eu");
            assertEquals("https://example.eu/auth/reset-password?token=tok123", resetLink(req));
        }
    }

    // ------------------------------------------- multi-domain / multi-locale

    @Nested
    class SiteAndLocaleSelection {

        @Test
        void aliasHostSelectsSameSiteButLinkUsesCanonicalHost() {
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "www.example.com"));
            assertTrue(link.startsWith("https://example.com/"));
        }

        @Test
        void idnSiteReachableByUnicodeAndPunycode() {
            assertEquals("https://xn--bcher-kva.example/auth/reset-password?token=tok123",
                    resetLink(TestRequest.viaTrustedProxy().header("Host", "bücher.example")));
            assertEquals("https://xn--bcher-kva.example/auth/reset-password?token=tok123",
                    resetLink(TestRequest.viaTrustedProxy().header("Host", "xn--bcher-kva.example")));
        }

        @Test
        void outerProxyBasePathIsPreserved() {
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "admin.example.com"));
            assertEquals("https://admin.example.com/console/auth/reset-password?token=tok123", link);
        }

        @Test
        void nonStandardPortComesFromConfig() {
            String link = resetLink(TestRequest.viaTrustedProxy().header("Host", "staging.internal.example"));
            assertEquals("https://staging.internal.example:8443/auth/reset-password?token=tok123", link);
        }

        @Test
        void nonDefaultLocaleGetsPathPrefix() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            assertEquals("https://example.com/en/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "en", "tok123"));
            assertEquals("https://example.com/en/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "EN", "tok123")); // case-insensitive
        }

        @Test
        void defaultLocaleHasNoPrefix() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            assertEquals("https://example.com/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "zh", "tok123"));
        }

        @Test
        void unsupportedLocaleFallsBackToSiteDefault() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            assertEquals("https://example.com/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "klingon", "tok123"));
        }

        @Test
        void localeCannotInjectPathSegments() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            String link = links.passwordResetLink(req, "../../attacker.example", "tok123");
            assertTrue(link.startsWith("https://example.com/auth/"));
        }

        @Test
        void euSiteLocalesAreIndependent() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.eu");
            assertEquals("https://example.eu/de/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "de", "tok123"));
            // "zh" is not served by the eu site -> falls back to eu default "en"
            assertEquals("https://example.eu/auth/reset-password?token=tok123",
                    links.passwordResetLink(req, "zh", "tok123"));
        }
    }

    // --------------------------------------------------- payload encoding

    @Nested
    class PayloadEncoding {

        @Test
        void resetTokenIsQueryEncoded() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            String link = links.passwordResetLink(req, "zh", "ab+c/d==");
            assertEquals("https://example.com/auth/reset-password?token=ab%2Bc%2Fd%3D%3D", link);
        }

        @Test
        void invitationIdCannotBreakOutOfPath() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            String link = links.invitationLink(req, "zh", "../../admin");
            assertEquals("https://example.com/invitations/..%2F..%2Fadmin", link);
        }

        @Test
        void shareLinkEncodesResourceParts() {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", "example.com");
            String link = links.shareLink(req, "zh", "doc", "a b/c");
            assertEquals("https://example.com/shared/doc/a%20b%2Fc", link);
        }
    }

    // ------------------------------------------- the pentest scenario, end to end

    @Test
    void pentestScenarioTokenNeverLeavesOurOrigins() {
        String[] tamperedHosts = {
                "attacker.example",
                "example.com.attacker.example",
                "example.com@attacker.example",
                "example.com:443@attacker.example",
                "attacker.example#example.com",
                "example.com.",
                "ATTACKER.EXAMPLE",
        };
        for (String host : tamperedHosts) {
            RequestView req = TestRequest.viaTrustedProxy().header("Host", host);
            String link = links.passwordResetLink(req, "zh", "secret-reset-token");
            assertTrue(link.startsWith("https://example.com/")
                            || link.startsWith("https://example.eu/")
                            || link.startsWith("https://admin.example.com/")
                            || link.startsWith("https://xn--bcher-kva.example/")
                            || link.startsWith("https://staging.internal.example:8443/"),
                    "host [" + host + "] produced off-site link: " + link);
            assertFalse(link.contains("attacker"), "host [" + host + "] leaked into link: " + link);
        }
    }
}
