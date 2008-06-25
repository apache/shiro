/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.filter.authc;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.util.StringUtils;
import org.jsecurity.web.RedirectView;
import org.jsecurity.web.WebUtils;
import static org.jsecurity.web.WebUtils.*;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;

/**
 * Requires the requesting user to be authenticated for the request to continue, and if they are not, forces the user
 * to login via by redirecting them to the {@link #setUrl(String) login page} you configure.
 *
 * <p>If the login attempt fails the AuthenticationException fully qualified class name will be placed as a request
 * attribute under the {@link #setFailureKeyAtribute(String) failureKeyAttribute} key.  This FQCN can then be used as
 * an i18n key or lookup mechanism that can then  be used to show the user why their login attempt failed
 * (e.g. no account, incorrect password, etc).
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class FormAuthenticationFilter extends AuthenticationFilter {

    public static final String DEFAULT_ERROR_KEY_ATTRIBUTE_NAME = FormAuthenticationFilter.class.getName() + "_AUTHC_FAILURE_KEY";

    public static final String DEFAULT_LOGIN_URL = "/login.jsp";
    public static final String DEFAULT_USERNAME_PARAM = "username";
    public static final String DEFAULT_PASSWORD_PARAM = "password";
    public static final String DEFAULT_REMEMBER_ME_PARAM = "rememberMe";

    private String usernameParam = DEFAULT_USERNAME_PARAM;
    private String passwordParam = DEFAULT_PASSWORD_PARAM;
    private String rememberMeParam = DEFAULT_REMEMBER_ME_PARAM;

    private String successUrl = DEFAULT_LOGIN_URL;
    private String failureKeyAtribute = DEFAULT_ERROR_KEY_ATTRIBUTE_NAME;

    public FormAuthenticationFilter() {
        setUrl(DEFAULT_LOGIN_URL);
    }

    public String getUsernameParam() {
        return usernameParam;
    }

    public void setUsernameParam(String usernameParam) {
        this.usernameParam = usernameParam;
    }

    public String getPasswordParam() {
        return passwordParam;
    }

    public void setPasswordParam(String passwordParam) {
        this.passwordParam = passwordParam;
    }

    public String getRememberMeParam() {
        return rememberMeParam;
    }

    public void setRememberMeParam(String rememberMeParam) {
        this.rememberMeParam = rememberMeParam;
    }

    public String getSuccessUrl() {
        return successUrl;
    }

    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }

    public String getFailureKeyAtribute() {
        return failureKeyAtribute;
    }

    public void setFailureKeyAtribute(String failureKeyAtribute) {
        this.failureKeyAtribute = failureKeyAtribute;
    }

    protected void onFilterConfigSet() throws Exception {
        if (log.isTraceEnabled()) {
            log.trace("Adding default login url to applied paths.");
        }
        this.appliedPaths.put(getUrl(), null);
    }

    protected boolean onUnauthenticatedRequest(ServletRequest request, ServletResponse response) throws Exception {
        if (isLoginRequest(request, response)) {
            if (isLoginSubmission(request, response)) {
                if (log.isTraceEnabled()) {
                    log.trace("Login submission detected.  Attempting to execute login.");
                }
                return executeLogin(request, response);
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("Login page view.");
                }
                //allow them to see the login page ;)
                return true;
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to access a path which requires authentication.  Forwarding to the " +
                        "Authentication url [" + getUrl() + "]");
            }
            issueRedirect(request, response);
            return false;
        }
    }

    protected void saveRequest(ServletRequest servletRequest, ServletResponse response) {
        //save the page they were trying to visit so we can redirect them back to this location after
        //a successful login:

        //TODO - JSEC-92
    }

    protected boolean isLoginSubmission(ServletRequest servletRequest, ServletResponse response) {
        return toHttp(servletRequest).getMethod().equalsIgnoreCase("POST");
    }

    protected boolean isLoginRequest(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = toHttp(servletRequest);
        String requestURI = getPathWithinApplication(request);
        return pathMatcher.match(getUrl(), requestURI);
    }

    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        String username = getUsername(request, response);
        String password = getPassword(request, response);
        boolean rememberMe = isRememberMe(request, response);
        InetAddress inet = getInetAddress(request, response);

        char[] passwordChars = null;
        if (password != null) {
            passwordChars = password.toCharArray();
        }

        UsernamePasswordToken token = new UsernamePasswordToken(username, passwordChars, rememberMe, inet);

        try {
            getSubject(request, response).login(token);
            issueSuccessRedirect(request, response);
            return false;
        } catch (AuthenticationException e) {
            String className = e.getClass().getName();
            request.setAttribute(getFailureKeyAtribute(), className);
            //login failed, let request continue back to the login page:
            return true;
        }
    }

    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
        RedirectView view = new RedirectView(getSuccessUrl(), isContextRelative(), isHttp10Compatible());
        view.renderMergedOutputModel(getQueryParams(), toHttp(request), toHttp(response));
    }

    protected String getUsername(ServletRequest request, ServletResponse response) {
        return StringUtils.clean(request.getParameter(getUsernameParam()));
    }

    protected String getPassword(ServletRequest request, ServletResponse response) {
        return StringUtils.clean(request.getParameter(getPasswordParam()));
    }

    protected boolean isRememberMe(ServletRequest request, ServletResponse response) {
        String rememberMe = StringUtils.clean(request.getParameter(getRememberMeParam()));
        return rememberMe != null &&
                (rememberMe.equalsIgnoreCase("true") ||
                        rememberMe.equalsIgnoreCase("t") ||
                        rememberMe.equalsIgnoreCase("1") ||
                        rememberMe.equalsIgnoreCase("y") ||
                        rememberMe.equalsIgnoreCase("yes") ||
                        rememberMe.equalsIgnoreCase("on"));
    }

    protected InetAddress getInetAddress(ServletRequest request, ServletResponse response) {
        return WebUtils.getInetAddress(request);
    }
}
