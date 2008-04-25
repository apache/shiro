package org.jsecurity.web.interceptor.authc;

import org.jsecurity.JSecurityException;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.util.StringUtils;
import org.jsecurity.web.RedirectView;
import org.jsecurity.web.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class FormAuthenticationWebInterceptor extends AuthenticationWebInterceptor {

    public static final String DEFAULT_ERROR_KEY_ATTRIBUTE_NAME = FormAuthenticationWebInterceptor.class.getName() + "_AUTHC_FAILURE_KEY";

    public static final String DEFAULT_LOGIN_URL = "/login.jsp";
    public static final String DEFAULT_USERNAME_PARAM = "username";
    public static final String DEFAULT_PASSWORD_PARAM = "password";
    public static final String DEFAULT_REMEMBER_ME_PARAM = "rememberMe";

    private String usernameParam = DEFAULT_USERNAME_PARAM;
    private String passwordParam = DEFAULT_PASSWORD_PARAM;
    private String rememberMeParam = DEFAULT_REMEMBER_ME_PARAM;

    private String successUrl = DEFAULT_LOGIN_URL;
    private String failureKeyAtribute = DEFAULT_ERROR_KEY_ATTRIBUTE_NAME;

    public FormAuthenticationWebInterceptor() {
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

    public void init() throws JSecurityException {
        if ( log.isTraceEnabled() ) {
            log.trace("Adding default login url to applied paths." );
        }
        this.appliedPaths.put(getUrl(),null);
    }

    protected boolean onUnauthenticatedRequest(ServletRequest request, ServletResponse response) throws Exception {
        if ( isLoginRequest(request,response) ) {
            if ( isLoginSubmission(request,response)) {
                if ( log.isTraceEnabled() ) {
                    log.trace("Login submission detected.  Attempting to execute login." );
                }
                return executeLogin(request, response);   
            } else {
                if ( log.isTraceEnabled() ) {
                    log.trace("Login page view.");
                }
                //allow them to see the login page ;)
                return true;
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace("Attempting to access a path which requires authentication.  Forwarding to the " +
                        "Authentication url [" + getUrl() + "]" );
            }
            issueRedirect(request,response);
            return false;
        }
    }

    protected void saveRequest(ServletRequest servletRequest, ServletResponse response ) {
        //save the page they were trying to visit so we can redirect them back to this location after
        //a successful login:

        //TODO - JSEC-92
    }

    protected boolean isLoginSubmission(ServletRequest servletRequest, ServletResponse response ) {
        return toHttp(servletRequest).getMethod().equalsIgnoreCase("POST");
    }

    protected boolean isLoginRequest(ServletRequest servletRequest, ServletResponse response ) {
        HttpServletRequest request = toHttp(servletRequest);
        String requestURI = WebUtils.getPathWithinApplication(request);
        return pathMatcher.match( getUrl(), requestURI );
    }

    protected boolean executeLogin(ServletRequest request, ServletResponse response ) throws Exception {
        String username = getUsername(request,response);
        String password = getPassword(request,response);
        boolean rememberMe = isRememberMe(request,response);
        InetAddress inet = getInetAddress(request,response);
        UsernamePasswordToken token = new UsernamePasswordToken(username, password.toCharArray(), rememberMe, inet );

        try {
            getSubject(request,response).login(token);
            issueSuccessRedirect(request,response);
            return false;
        } catch (AuthenticationException e) {
            String className = e.getClass().getName();
            request.setAttribute(getFailureKeyAtribute(), className );
            //login failed, let request continue back to the login page:
            return true;
        }
    }

    protected void issueSuccessRedirect( ServletRequest request, ServletResponse response ) throws Exception {
        RedirectView view = new RedirectView( getSuccessUrl(), isContextRelative(), isHttp10Compatible() );
        view.renderMergedOutputModel(getQueryParams(), toHttp(request), toHttp(response) );
    }

    protected String getUsername( ServletRequest request, ServletResponse response ) {
        return StringUtils.clean(request.getParameter(getUsernameParam()));
    }

    protected String getPassword( ServletRequest request, ServletResponse response ) {
        return StringUtils.clean(request.getParameter(getPasswordParam()));
    }

    protected boolean isRememberMe( ServletRequest request, ServletResponse response ) {
        String rememberMe = StringUtils.clean(request.getParameter(getRememberMeParam()));
        return rememberMe != null &&
                (rememberMe.equalsIgnoreCase("true") ||
                 rememberMe.equalsIgnoreCase("1") ||
                 rememberMe.equalsIgnoreCase("y") || 
                 rememberMe.equalsIgnoreCase("yes" ) );
    }

    protected InetAddress getInetAddress( ServletRequest request, ServletResponse response ) {
        if ( request instanceof HttpServletRequest ) {
            try {
                return InetAddress.getByName( toHttp(request).getRemoteAddr() );
            } catch (UnknownHostException e) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "Unable to acquire host for HttpServlet request.", e );
                }
            }
        }
        return null;
    }
}
