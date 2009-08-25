package org.apache.shiro.subject;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * Builder design pattern implementation for acquiring {@link Subject} instances in a simplified way without having
 * to know Shiro's construction techniques.
 * <h4>Usage</h4>
 * The simplest usage of this builder is to construct an anonymous, session-less {@code Subject} instance:
 * <pre>
 * SecurityManager securityManager = //obtain from application configuration
 * Subject subject = new {@link #SubjectBuilder(SecurityManager) SubjectBuilder}(securityManager).{@link #buildSubject() build()};</pre>
 * <p/>
 * Any of the {@code set*} methods may be called before the {@link #buildSubject () build()} call to provide context
 * on how to construct the {@code Subject} instance.  For example, if you have a session id and want to acquire the
 * subject that owns that session (assuming the session exists and is not expired):
 * <pre>
 * SecurityManager securityManager = //obtain from application configuration
 * Subject subject = SubjectBuilder.newBuilder(securityManager)
 * .setSessionId(sessionId)
 * .build();</pre>
 * <p/>
 * Similarly, if you want a Subject instance reflecting a certain identity:
 * <pre>
 * PrincipalCollection principals = new SimplePrincipalCollection("username", "myRealm");
 * Subject subject = SubjectBuilder.newBuilder(securityManager).setPrincipals(principals).build();</pre>
 * <p/>
 * Note that the returned {@code Subject} instance is <b>not</b> automatically bound to the application for further use,
 * that is, {@link org.apache.shiro.SecurityUtils SecurityUtils}.{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}
 * will not automatically return the same instance as what is returned by the builder.
 *
 * @since 1.0
 */
public class SubjectBuilder {

    private final Map<String, Object> subjectContext;

    private final SecurityManager securityManager;

    public SubjectBuilder() {
        this(SecurityUtils.getSecurityManager());
    }

    public SubjectBuilder(SecurityManager securityManager) {
        if (securityManager == null) {
            throw new NullPointerException("SecurityManager method argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.subjectContext = new HashMap<String, Object>();
    }

    protected Map<String, Object> getSubjectContext() {
        return this.subjectContext;
    }

    public SubjectBuilder setSessionId(Serializable sessionId) {
        if (sessionId != null) {
            this.subjectContext.put(SubjectFactory.SESSION_ID, sessionId);
        }
        return this;
    }

    public SubjectBuilder setInetAddress(InetAddress originatingHost) {
        if (originatingHost != null) {
            this.subjectContext.put(SubjectFactory.INET_ADDRESS, originatingHost);
        }
        return this;
    }

    public SubjectBuilder setSession(Session session) {
        if (session != null) {
            this.subjectContext.put(SubjectFactory.SESSION, session);
        }
        return this;
    }

    public SubjectBuilder setPrincipals(PrincipalCollection principals) {
        if (principals != null && !principals.isEmpty()) {
            this.subjectContext.put(SubjectFactory.PRINCIPALS, principals);
        }
        return this;
    }

    public SubjectBuilder setAuthenticated(boolean authenticated) {
        this.subjectContext.put(SubjectFactory.AUTHENTICATED, authenticated);
        return this;
    }

    public Subject buildSubject() {
        return this.securityManager.createSubject(this.subjectContext);
    }


}
