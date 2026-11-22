package com.example.links;

import java.util.List;

/**
 * Minimal, framework-agnostic view of the inbound HTTP request.
 *
 * <p>Implement this once per web framework (Servlet, Spring WebFlux, JAX-RS, ...).
 * The security rule enforced by this library is that a {@link RequestView} can only
 * <em>select</em> one of the pre-configured sites — it can never introduce a host,
 * scheme or port that is not present in {@link PublicUrlConfig}.</p>
 *
 * <p>Servlet adapter sketch:</p>
 * <pre>{@code
 * RequestView view = new RequestView() {
 *     public String remoteAddr()          { return req.getRemoteAddr(); }
 *     public String scheme()              { return req.getScheme(); }
 *     public String header(String name)   { return req.getHeader(name); }
 *     public List<String> headers(String name) {
 *         return Collections.list(req.getHeaders(name));
 *     }
 * };
 * }</pre>
 */
public interface RequestView {

    /** IP of the direct TCP peer (usually the last reverse proxy), e.g. "10.1.2.3". */
    String remoteAddr();

    /** Scheme of the direct connection, e.g. "https". Informational only. */
    String scheme();

    /** First value of the given header, or {@code null}. Header names are case-insensitive. */
    String header(String name);

    /** All values of the given header (never {@code null}). */
    List<String> headers(String name);
}
