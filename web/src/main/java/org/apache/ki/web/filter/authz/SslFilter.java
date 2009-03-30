package org.apache.ki.web.filter.authz;

/**
 * Convenience filter which requires a request to be over SSL.  This filter has the same effect as of using the
 * {@link PortFilter} with configuration defaulting to port {@code 443}.  That is, these two configs are the same:
 *
 * <pre>
 * /some/path/** = port[443]
 * /some/path/** = ssl
 * </pre>
 *
 * @author Les Hazlewood
 * @since Mar 30, 2009 12:16:14 PM
 */
public class SslFilter extends PortFilter {

    public static final int DEFAULT_SSL_PORT = 443;

    @Override
    protected int toPort(Object mappedValue) {
        String[] ports = (String[]) mappedValue;
        if (ports == null || ports.length == 0) {
            return DEFAULT_SSL_PORT;
        }
        return super.toPort(mappedValue);
    }
}
