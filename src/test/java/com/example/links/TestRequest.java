package com.example.links;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Simple in-memory {@link RequestView} for tests. */
final class TestRequest implements RequestView {

    static final String TRUSTED_PROXY = "10.1.2.3";
    static final String ATTACKER_IP = "203.0.113.9";

    private final String remoteAddr;
    private final Map<String, List<String>> headers = new LinkedHashMap<>();

    private TestRequest(String remoteAddr) {
        this.remoteAddr = remoteAddr;
    }

    static TestRequest from(String remoteAddr) {
        return new TestRequest(remoteAddr);
    }

    static TestRequest viaTrustedProxy() {
        return new TestRequest(TRUSTED_PROXY);
    }

    static TestRequest direct() {
        return new TestRequest(ATTACKER_IP);
    }

    TestRequest header(String name, String value) {
        headers.computeIfAbsent(name.toLowerCase(), k -> new ArrayList<>()).add(value);
        return this;
    }

    @Override
    public String remoteAddr() {
        return remoteAddr;
    }

    @Override
    public String scheme() {
        return "http";
    }

    @Override
    public String header(String name) {
        List<String> v = headers.get(name.toLowerCase());
        return (v == null || v.isEmpty()) ? null : v.get(0);
    }

    @Override
    public List<String> headers(String name) {
        return headers.getOrDefault(name.toLowerCase(), List.of());
    }
}
