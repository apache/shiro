package org.jsecurity.web.authz;

import org.jsecurity.SecurityManager;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public interface UrlAuthorizationHandler {

    boolean configureUrlAuthorization(SecurityManager securityManager, FilterConfig config);

    boolean isUserAuthorizedForRequest(HttpServletRequest request);

}
