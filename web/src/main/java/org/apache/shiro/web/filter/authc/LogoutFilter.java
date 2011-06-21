package org.apache.shiro.web.filter.authc;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Simple Filter that, upon receiving a request, will immediately log-out the currently executing
 * {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) subject}
 * and then redirect them to a configured {@link #getRedirectUrl() redirectUrl}.
 *
 * @since 1.2
 */
public class LogoutFilter extends AdviceFilter {

    /**
     * The default redirect URL to where the user will be redirected after logout.  The value is {@code "/"}, Shiro's
     * representation of the web application's context root.
     */
    public static final String DEFAULT_REDIRECT_URL = "/";

    /**
     * The URL to where the user will be redirected after logout.
     */
    private String redirectUrl = DEFAULT_REDIRECT_URL;

    /**
     * Immediately logs out the currently executing {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) subject}
     * and redirects the end-user to the configured {@link #getRedirectUrl() redirectUrl}.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code false} always as typically no further interaction should be done after user logout.
     * @throws Exception if there is any error.
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        subject.logout();
        issueRedirect(request, response);
        return false;
    }

    /**
     * Returns the currently executing {@link Subject}.  This implementation merely defaults to calling
     * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}, but can be overridden
     * by subclasses for different retrieval strategies.
     *
     * @param request  the incoming Servlet request
     * @param response the outgoing Servlet response
     * @return the currently executing {@link Subject}.
     */
    protected Subject getSubject(ServletRequest request, ServletResponse response) {
        return SecurityUtils.getSubject();
    }

    /**
     * Issues an HTTP redirect after subject logout.  This implementation acquires the redirect URL returned from
     * {@link #getRedirectUrl(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} and then calls
     * {@code WebUtils.}{@link WebUtils#issueRedirect(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String) issueRedirect(request,response,redirectUrl)}.
     *
     * @param request  the incoming Servlet request
     * @param response the outgoing Servlet response
     * @throws Exception if there is any error.
     */
    protected void issueRedirect(ServletRequest request, ServletResponse response) throws Exception {
        String redirectUrl = getRedirectUrl(request, response);
        WebUtils.issueRedirect(request, response, redirectUrl);
    }

    /**
     * Returns the redirect URL to send the user after logout.  This default implementation returns the static
     * configured {@link #getRedirectUrl() redirectUrl} property, but this method may be overridden by subclasses
     * to dynamically construct the URL if necessary.
     *
     * @param request the incoming Servlet request
     * @param response the outgoing ServletResponse
     * @return the redirect URL to send the user after logout.
     */
    protected String getRedirectUrl(ServletRequest request, ServletResponse response) {
        return getRedirectUrl();
    }

    /**
     * Returns the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @return the URL to where the user will be redirected after logout.
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Sets the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @param redirectUrl the url to where the user will be redirected after logout
     */
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}
