package org.apache.shiro.web.mgt;

import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.subject.WebDelegatingSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.Map;

/**
 * A {@code SubjectFactory} implementation that creates {@link WebDelegatingSubject} instances.
 * <p/>
 * {@code WebDelegatingSubject} instances are required if Request/Response objects are to be maintained across
 * threads when using the {@code Subject} {@link Subject#createCallable(java.util.concurrent.Callable) createCallable}
 * and {@link Subject#createRunnable(Runnable) createRunnable} methods.
 *
 * @see #newSubjectInstance(org.apache.shiro.subject.PrincipalCollection, boolean, java.net.InetAddress, org.apache.shiro.session.Session, org.apache.shiro.mgt.SecurityManager)
 * @since 1.0
 */
public class DefaultWebSubjectFactory extends DefaultSubjectFactory {

    public DefaultWebSubjectFactory() {
        super();
    }

    public DefaultWebSubjectFactory(SecurityManager securityManager) {
        super(securityManager);
    }

    protected ServletRequest getServletRequest(Map context) {
        ServletRequest request = getTypedValue(context, SubjectFactory.SERVLET_REQUEST, ServletRequest.class);
        if (request == null) {
            throw new IllegalStateException("Subject context map must contain a " +
                    ServletRequest.class.getName() + " instance to support Web Subject construction.");
        }
        return request;
    }

    protected ServletResponse getServletResponse(Map context) {
        ServletResponse response = getTypedValue(context, SubjectFactory.SERVLET_RESPONSE, ServletResponse.class);
        if (response == null) {
            throw new IllegalStateException("Subject context map must contain a " +
                    ServletResponse.class.getName() + " instance to support Web Subject construction.");
        }
        return response;
    }

    @Override
    protected InetAddress getInetAddress(Map context, Session session) {
        InetAddress inet = super.getInetAddress(context, session);
        if (inet == null) {
            ServletRequest request = getServletRequest(context);
            inet = WebUtils.getInetAddress(request);
        }
        return inet;
    }

    public Subject createSubject(Map context) {
        Session session = getSession(context);
        PrincipalCollection principals = getPrincipals(context, session);
        boolean authenticated = isAuthenticated(context, session);
        InetAddress inet = getInetAddress(context, session);
        ServletRequest request = getServletRequest(context);
        ServletResponse response = getServletResponse(context);
        return newSubjectInstance(principals, authenticated, inet, session, request, response, getSecurityManager());
    }

    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated,
                                         InetAddress inet, Session session,
                                         ServletRequest request, ServletResponse response,
                                         SecurityManager securityManager) {
        return new WebDelegatingSubject(principals, authenticated, inet, session, request, response, securityManager);
    }
}
