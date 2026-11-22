package com.example.links;

import java.util.List;
import java.util.Map;

/**
 * The single entry point feature code uses for every link that leaves the system
 * (emails, SMS, API responses, share dialogs).
 *
 * <p>Password reset, email verification, invitations and share links all funnel
 * through here, so the host-whitelist policy is applied in exactly one place.
 * When you audit the codebase, every outbound-link feature should call this
 * service — nothing should call {@code request.getRequestURL()},
 * {@code ServletUriComponentsBuilder}, or read {@code Host} headers directly.</p>
 */
public final class OutboundLinkService {

    private final PublicOriginResolver originResolver;
    private final LinkBuilder linkBuilder;

    public OutboundLinkService(PublicUrlConfig config) {
        this.originResolver = new PublicOriginResolver(config);
        this.linkBuilder = new LinkBuilder();
    }

    /** Link emailed by the "forgot password" flow. Carries the one-time reset token. */
    public String passwordResetLink(RequestView request, String userLocale, String resetToken) {
        PublicOrigin origin = originResolver.resolve(request);
        return linkBuilder.build(origin, userLocale, "/auth/reset-password",
                Map.of("token", resetToken));
    }

    /** Link emailed to verify a mailbox. */
    public String emailVerificationLink(RequestView request, String userLocale, String verificationToken) {
        PublicOrigin origin = originResolver.resolve(request);
        return linkBuilder.build(origin, userLocale, "/auth/verify-email",
                Map.of("token", verificationToken));
    }

    /** Link emailed to an invitee. */
    public String invitationLink(RequestView request, String userLocale, String invitationId) {
        PublicOrigin origin = originResolver.resolve(request);
        return linkBuilder.build(origin, userLocale, "/invitations",
                List.of(invitationId), Map.of());
    }

    /** Link for sharing a resource with someone. */
    public String shareLink(RequestView request, String userLocale, String resourceType, String resourceId) {
        PublicOrigin origin = originResolver.resolve(request);
        return linkBuilder.build(origin, userLocale, "/shared",
                List.of(resourceType, resourceId), Map.of());
    }
}
