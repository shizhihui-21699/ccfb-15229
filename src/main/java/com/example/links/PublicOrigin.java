package com.example.links;

/**
 * The resolved, trustworthy public origin for one request — the only thing
 * application code is allowed to build outbound links from.
 */
public final class PublicOrigin {

    private final String scheme;
    private final Site site;

    PublicOrigin(String scheme, Site site) {
        this.scheme = scheme;
        this.site = site;
    }

    public String scheme() {
        return scheme;
    }

    public Site site() {
        return site;
    }

    /** e.g. {@code https://www.example.com} (plus non-standard port if configured). */
    public String origin() {
        StringBuilder sb = new StringBuilder(scheme).append("://").append(site.canonicalHost());
        if (site.port() > 0) {
            sb.append(':').append(site.port());
        }
        return sb.toString();
    }

    /** Origin plus the fixed base path of the site, e.g. {@code https://admin.example.com/console}. */
    public String baseUrl() {
        return origin() + site.basePath();
    }

    @Override
    public String toString() {
        return baseUrl();
    }
}
