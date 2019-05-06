package org.apache.shiro.authc;


/**
 * A {@link AuthenticationToken} that contains an a Bearer token or API key, typically received via an HTTP {@code Authorization} header. This
 * class also implements the {@link org.apache.shiro.authc.HostAuthenticationToken HostAuthenticationToken} interface to retain the host name
 * or IP address location from where the authentication attempt is occurring.
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2.1">OAuth2 Authorization Request Header Field</a>
 *
 * @since 1.5
 */
public class BearerToken implements HostAuthenticationToken {

    private final String token;

    /**
     * The location from where the login attempt occurs, or <code>null</code> if not known or explicitly
     * omitted.
     */
    private String host;

    public BearerToken(String token) {
        this(token, null);
    }

    public BearerToken(String token, String host) {
        this.token = token;
        this.host = host;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    public String getToken() {
        return token;
    }
}
