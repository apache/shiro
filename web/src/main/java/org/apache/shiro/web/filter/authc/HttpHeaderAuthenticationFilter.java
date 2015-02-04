package org.apache.shiro.web.filter.authc;

import com.google.common.collect.Lists;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.AuthorizingSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;

public class HttpHeaderAuthenticationFilter extends AuthenticatingFilter {
    public final String REMOTE_USERNAME_HEADER = "X-Forwarded-User";
    public final String REMOTE_HOST_HEADER = "X-Forwarded-Host";

    private static final Logger log = LoggerFactory.getLogger(HttpHeaderAuthenticationFilter.class);

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false;
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        AuthenticationToken token = getLoginToken(request, response);
        if (token == null) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN);
            return false;
        } else {
            DelegatingSubject subject = getDelegatingSubject(request, response, token);
            Object roles = getRoles(subject);
            log.debug("Subject {} hasRoles {}", subject.getPrincipal(), roles);
            return true;
        }
    }

    private List<String> getRoles(DelegatingSubject subject) {
        AuthorizingSecurityManager secMgr = (AuthorizingSecurityManager) subject.getSecurityManager();
        Collection<Realm> realms = secMgr.getRealms();
        List<String> authRoles = Lists.newArrayList();

        for (Realm realm : realms) {
            if(realm instanceof AuthorizingRealm) {
                AuthorizingRealm authRealm = (AuthorizingRealm) realm;
                authRoles.addAll(authRealm.getAuthorizationInfo(subject.getPrincipals()).getRoles());
            }
        }

        return authRoles;
    }

    protected AuthenticationToken getLoginToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (!isHttpLogin(request)) {
            log.error("Attempting to access URI " + httpRequest.getRequestURI() + " without an authentication token");
            return null;
        } else {
            return createToken(request, response);
        }
    }

    private DelegatingSubject getDelegatingSubject(ServletRequest request, ServletResponse response, AuthenticationToken token) {
        DelegatingSubject subject = (DelegatingSubject) getSubject(request, response);
        subject.login(token);
        return subject;
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = ((HttpServletRequest) request);
        String username = httpRequest.getHeader(REMOTE_USERNAME_HEADER);
        String host = httpRequest.getHeader(REMOTE_HOST_HEADER);
        return new UsernamePasswordToken(username, new char[0], host);
    }

    private boolean isHttpLogin(ServletRequest request) {
        return ((HttpServletRequest) request).getHeader(REMOTE_USERNAME_HEADER) != null;
    }
}
