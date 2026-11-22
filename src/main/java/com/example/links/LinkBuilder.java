package com.example.links;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Builds absolute outbound links from a resolved {@link PublicOrigin}.
 *
 * <p>All variable parts (tokens, ids, locales) are validated or percent-encoded
 * here, so callers cannot accidentally smuggle delimiters into a URL.</p>
 */
public final class LinkBuilder {

    /**
     * @param origin          resolved origin for the current request
     * @param requestedLocale user's locale; resolved against the site's supported locales
     * @param path            app-relative path starting with '/', e.g. "/auth/reset-password"
     * @param query           query parameters, values are percent-encoded
     */
    public String build(PublicOrigin origin, String requestedLocale, String path, Map<String, String> query) {
        return build(origin, requestedLocale, path, List.of(), query);
    }

    /**
     * Like {@link #build(PublicOrigin, String, String, Map)}, with extra variable
     * path segments appended after the static path. Each segment is percent-encoded
     * individually, so ids containing '/' or '..' cannot traverse the path.
     */
    public String build(PublicOrigin origin, String requestedLocale, String path,
                        List<String> pathSegments, Map<String, String> query) {
        if (!path.startsWith("/") || path.contains("..") || path.contains("//")) {
            throw new IllegalArgumentException("path must be app-relative and clean: " + path);
        }
        Site site = origin.site();
        String locale = site.resolveLocale(requestedLocale);

        StringBuilder sb = new StringBuilder(origin.baseUrl());
        sb.append(site.localePrefix(locale));
        sb.append(path);
        if (pathSegments != null) {
            for (String segment : pathSegments) {
                sb.append('/').append(encodePathSegment(segment));
            }
        }

        if (query != null && !query.isEmpty()) {
            char sep = '?';
            for (Map.Entry<String, String> e : query.entrySet()) {
                sb.append(sep);
                sep = '&';
                sb.append(encodeQuery(e.getKey())).append('=').append(encodeQuery(e.getValue()));
            }
        }
        return sb.toString();
    }

    /** Percent-encodes a single path segment (tokens, invitation ids, ...). */
    public static String encodePathSegment(String value) {
        // URLEncoder is form-oriented; fix up the differences for path segments.
        return URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("%7E", "~");
    }

    private static String encodeQuery(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
