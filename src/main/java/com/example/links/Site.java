package com.example.links;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * One externally reachable site: a set of equivalent hostnames, the locales it
 * serves, and the fixed base path the outermost reverse proxy exposes it under.
 *
 * <p>Everything in here is server-side configuration. Request data can select a
 * site, but can never modify one.</p>
 */
public final class Site {

    private final String id;
    private final Set<String> hosts;          // normalized, first entry is canonical
    private final String defaultLocale;
    private final Set<String> supportedLocales;
    private final String basePath;            // "" or "/prefix" (no trailing slash)
    private final int port;                   // -1 = omit from generated links

    private Site(Builder b) {
        this.id = Objects.requireNonNull(b.id, "id");
        if (b.hosts.isEmpty()) {
            throw new IllegalArgumentException("site '" + b.id + "' needs at least one host");
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String h : b.hosts) {
            String n = HostNormalizer.normalize(h);
            if (n == null) {
                throw new IllegalArgumentException("invalid host for site '" + b.id + "': " + h);
            }
            normalized.add(n);
        }
        this.hosts = Set.copyOf(normalized);
        // LinkedHashSet.copyOf does not guarantee order; keep canonical separately.
        this.canonicalHost = normalized.iterator().next();
        this.defaultLocale = normalizeLocale(Objects.requireNonNull(b.defaultLocale, "defaultLocale"));
        Set<String> locales = new LinkedHashSet<>();
        locales.add(this.defaultLocale);
        for (String l : b.supportedLocales) {
            locales.add(normalizeLocale(l));
        }
        this.supportedLocales = Set.copyOf(locales);
        this.basePath = normalizeBasePath(b.basePath);
        this.port = b.port;
    }

    private final String canonicalHost;

    public static Builder builder(String id) {
        return new Builder(id);
    }

    public String id() {
        return id;
    }

    /** The host actually placed into generated links. */
    public String canonicalHost() {
        return canonicalHost;
    }

    /** All normalized hostnames that map to this site (canonical + aliases). */
    public Set<String> hosts() {
        return hosts;
    }

    public String defaultLocale() {
        return defaultLocale;
    }

    public Set<String> supportedLocales() {
        return supportedLocales;
    }

    /** Fixed path prefix the outermost proxy exposes, "" or "/prefix". */
    public String basePath() {
        return basePath;
    }

    /** Port to place into generated links, or -1 to omit. */
    public int port() {
        return port;
    }

    /**
     * Resolves a requested locale (user profile, Accept-Language, ...) to one this
     * site actually serves. Unknown or null locales fall back to the site default —
     * the request can never inject a path segment here.
     */
    public String resolveLocale(String requested) {
        if (requested != null) {
            String n = normalizeLocale(requested);
            if (supportedLocales.contains(n)) {
                return n;
            }
        }
        return defaultLocale;
    }

    /** URL path prefix for a resolved locale: "" for the default locale, "/en" etc. otherwise. */
    public String localePrefix(String resolvedLocale) {
        return resolvedLocale.equals(defaultLocale) ? "" : "/" + resolvedLocale;
    }

    static String normalizeLocale(String locale) {
        return locale.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    private static String normalizeBasePath(String basePath) {
        if (basePath == null || basePath.isBlank() || basePath.equals("/")) {
            return "";
        }
        String p = basePath.trim();
        if (!p.startsWith("/")) {
            throw new IllegalArgumentException("basePath must start with '/': " + basePath);
        }
        while (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (p.contains("..") || p.contains("//")) {
            throw new IllegalArgumentException("invalid basePath: " + basePath);
        }
        return p;
    }

    public static final class Builder {
        private final String id;
        private final Set<String> hosts = new LinkedHashSet<>();
        private String defaultLocale;
        private final Set<String> supportedLocales = new LinkedHashSet<>();
        private String basePath = "";
        private int port = -1;

        private Builder(String id) {
            this.id = id;
        }

        /** First host added is the canonical one used in generated links. */
        public Builder host(String host) {
            this.hosts.add(host);
            return this;
        }

        public Builder defaultLocale(String locale) {
            this.defaultLocale = locale;
            return this;
        }

        public Builder supportedLocale(String locale) {
            this.supportedLocales.add(locale);
            return this;
        }

        /** Fixed path prefix under which the outermost reverse proxy exposes this site. */
        public Builder basePath(String basePath) {
            this.basePath = basePath;
            return this;
        }

        /** Non-standard public port (e.g. 8443 in a staging environment). */
        public Builder port(int port) {
            this.port = port;
            return this;
        }

        public Site build() {
            return new Site(this);
        }
    }
}
