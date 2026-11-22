package com.example.links;

import java.util.List;
import java.util.Locale;

/**
 * Resolves the {@link PublicOrigin} for an inbound request.
 *
 * <p>Security invariants:</p>
 * <ul>
 *   <li>The host in a generated link always comes from {@link PublicUrlConfig};
 *       request headers can only <em>select</em> a configured site.</li>
 *   <li>{@code X-Forwarded-Host} / {@code X-Forwarded-Proto} are only read when the
 *       direct TCP peer is a configured trusted proxy.</li>
 *   <li>Anything unrecognized — tampered, malformed, or simply unknown — falls back
 *       to the default site. There is no code path that puts attacker input into a
 *       link.</li>
 * </ul>
 */
public final class PublicOriginResolver {

    private final PublicUrlConfig config;

    public PublicOriginResolver(PublicUrlConfig config) {
        this.config = config;
    }

    public PublicOrigin resolve(RequestView request) {
        boolean fromTrustedProxy = config.isTrustedProxy(request.remoteAddr());

        // 1. Pick the host candidate. Forwarded headers win only behind our own proxies.
        String candidate = null;
        if (fromTrustedProxy) {
            candidate = firstForwardedValue(request.headers("X-Forwarded-Host"));
        }
        if (candidate == null) {
            candidate = request.header("Host");
        }

        // 2. The candidate is only a lookup key into the whitelist.
        String normalized = HostNormalizer.normalize(candidate);
        Site site = normalized != null
                ? config.findByHost(normalized).orElse(config.defaultSite())
                : config.defaultSite();

        // 3. Scheme: https unless config explicitly allows http and a trusted proxy
        //    told us the client connection was plain http.
        String scheme = "https";
        if (!config.httpsOnly() && fromTrustedProxy) {
            String proto = firstForwardedValue(request.headers("X-Forwarded-Proto"));
            if (proto != null) {
                String p = proto.trim().toLowerCase(Locale.ROOT);
                if (p.equals("http") || p.equals("https")) {
                    scheme = p;
                }
                // anything else ("javascript:", "data:", garbage) -> keep default
            }
        }

        return new PublicOrigin(scheme, site);
    }

    /**
     * First element of a (possibly comma-joined) forwarded header list — the value
     * closest to the original client. It is still only used as a whitelist key.
     */
    private static String firstForwardedValue(List<String> values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v == null) {
                continue;
            }
            int comma = v.indexOf(',');
            String first = (comma >= 0 ? v.substring(0, comma) : v).trim();
            if (!first.isEmpty()) {
                return first;
            }
        }
        return null;
    }
}
