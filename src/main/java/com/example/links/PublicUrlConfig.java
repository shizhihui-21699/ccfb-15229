package com.example.links;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Server-side configuration for every externally reachable origin.
 *
 * <p>This is the single source of truth for hosts, schemes, ports and base paths
 * that may appear in links sent to users. Load it per environment (dev / staging /
 * prod) from your normal config mechanism — properties, YAML, environment
 * variables — never from request data.</p>
 */
public final class PublicUrlConfig {

    private final Map<String, Site> sitesById;
    private final Map<String, Site> sitesByHost;
    private final Site defaultSite;
    private final TrustedProxyMatcher trustedProxies;
    private final boolean httpsOnly;

    private PublicUrlConfig(Builder b) {
        if (b.sites.isEmpty()) {
            throw new IllegalArgumentException("at least one site is required");
        }
        this.sitesById = new LinkedHashMap<>();
        this.sitesByHost = new LinkedHashMap<>();
        for (Site s : b.sites) {
            if (sitesById.putIfAbsent(s.id(), s) != null) {
                throw new IllegalArgumentException("duplicate site id: " + s.id());
            }
            for (String host : s.hosts()) {
                if (sitesByHost.putIfAbsent(host, s) != null) {
                    throw new IllegalArgumentException("host claimed by two sites: " + host);
                }
            }
        }
        Site def = b.defaultSiteId != null ? sitesById.get(b.defaultSiteId) : b.sites.get(0);
        if (def == null) {
            throw new IllegalArgumentException("unknown default site: " + b.defaultSiteId);
        }
        this.defaultSite = def;
        this.trustedProxies = b.trustedProxies;
        this.httpsOnly = b.httpsOnly;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Site defaultSite() {
        return defaultSite;
    }

    /** Looks up a site by an already-normalized host. */
    public Optional<Site> findByHost(String normalizedHost) {
        return Optional.ofNullable(sitesByHost.get(normalizedHost));
    }

    /** True if the direct TCP peer is a reverse proxy we configured ourselves. */
    public boolean isTrustedProxy(String remoteAddr) {
        return trustedProxies.matches(remoteAddr);
    }

    /** When true, generated links always use https regardless of forwarded headers. */
    public boolean httpsOnly() {
        return httpsOnly;
    }

    public static final class Builder {
        private final List<Site> sites = new ArrayList<>();
        private String defaultSiteId;
        private TrustedProxyMatcher trustedProxies = TrustedProxyMatcher.none();
        private boolean httpsOnly = true;

        public Builder site(Site site) {
            this.sites.add(site);
            return this;
        }

        /** Fallback site used when the request host matches nothing (or is hostile). */
        public Builder defaultSite(String siteId) {
            this.defaultSiteId = siteId;
            return this;
        }

        /** CIDR ranges of your own reverse proxies / load balancers. */
        public Builder trustedProxies(List<String> cidrs) {
            this.trustedProxies = TrustedProxyMatcher.of(cidrs);
            return this;
        }

        /** Default true: outbound links are always https. */
        public Builder httpsOnly(boolean httpsOnly) {
            this.httpsOnly = httpsOnly;
            return this;
        }

        public PublicUrlConfig build() {
            return new PublicUrlConfig(this);
        }
    }

    @Override
    public String toString() {
        return "PublicUrlConfig" + sitesById.keySet();
    }

    @Override
    public boolean equals(Object o) {
        return this == o;
    }

    @Override
    public int hashCode() {
        return Objects.hash(sitesById.keySet(), defaultSite.id());
    }
}
