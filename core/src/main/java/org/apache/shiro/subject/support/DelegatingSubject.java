/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.subject.support;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.ProxiedSession;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionContext;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.subject.ExecutionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Implementation of the {@code Subject} interface that delegates
 * method calls to an underlying {@link org.apache.shiro.mgt.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a {@code SecurityManager} proxy.
 * <p/>
 * This implementation does not maintain state such as roles and permissions (only {@code Subject}
 * {@link #getPrincipals() principals}, such as usernames or user primary keys) for better performance in a stateless
 * architecture.  It instead asks the underlying {@code SecurityManager} every time to perform
 * the authorization check.
 * <p/>
 * A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying {@code SecurityManager} instance.  If caching of authorization
 * data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying {@code SecurityManager} implementation or its delegate components
 * manage caching, not this class.  A {@code SecurityManager} is considered a business-tier component,
 * where caching strategies are better suited.
 * <p/>
 * Applications from large and clustered to simple and JVM-local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 *
 * @since 0.1
 */
public class DelegatingSubject implements Subject, Serializable {

    private static final long serialVersionUID = -5094259915319399138L;

    private static final Logger log = LoggerFactory.getLogger(DelegatingSubject.class);

    private static final String RUN_AS_PRINCIPALS_SESSION_KEY =
            DelegatingSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

    protected PrincipalCollection principals;
    protected boolean authenticated;
    protected String host;
    protected Session session;
    private List<PrincipalCollection> runAsPrincipals; //supports assumed identities (aka 'run as')

    protected transient SecurityManager securityManager;

    public DelegatingSubject(SecurityManager securityManager) {
        this(null, false, null, null, securityManager);
    }

    public DelegatingSubject(PrincipalCollection principals, boolean authenticated, String host,
                             Session session, SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.principals = principals;
        this.authenticated = authenticated;
        this.host = host;
        if (session != null) {
            this.session = decorate(session);
            this.runAsPrincipals = getRunAsPrincipals(this.session);
        }
    }

    protected Session decorate(Session session) {
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        return new StoppingAwareProxiedSession(session, this);
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected boolean hasPrincipals() {
        return !CollectionUtils.isEmpty(getPrincipals());
    }

    /**
     * Returns the host name or IP associated with the client who created/is interacting with this Subject.
     *
     * @return the host name or IP associated with the client who created/is interacting with this Subject.
     */
    public String getHost() {
        return this.host;
    }

    private Object getPrimaryPrincipal(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            return principals.getPrimaryPrincipal();
        }
        return null;
    }

    /**
     * @see Subject#getPrincipal()
     */
    public Object getPrincipal() {
        return getPrimaryPrincipal(getPrincipals());
    }

    public PrincipalCollection getPrincipals() {
        return CollectionUtils.isEmpty(this.runAsPrincipals) ? this.principals : this.runAsPrincipals.get(0);
    }

    public boolean isPermitted(String permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean isPermitted(Permission permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean[] isPermitted(String... permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.length];
        }
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean isPermittedAll(String... permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipals()) {
            String msg = "This subject is anonymous - it does not have any identifying principals and " +
                    "authorization operations require an identity to check against.  A Subject instance will " +
                    "acquire these identifying principals automatically after a successful login is performed " +
                    "be executing " + Subject.class.getName() + ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled by the SecurityManager.  This exception can also occur when a " +
                    "previously logged-in Subject has logged out which " +
                    "makes it anonymous again.  Because an identity is currently not known due to any of these " +
                    "conditions, authorization is denied.";
            throw new UnauthenticatedException(msg);
        }
    }

    public void checkPermission(String permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermissions(String... permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public boolean hasRole(String roleIdentifier) {
        return hasPrincipals() && securityManager.hasRole(getPrincipals(), roleIdentifier);
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        if (hasPrincipals()) {
            return securityManager.hasRoles(getPrincipals(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        return hasPrincipals() && securityManager.hasAllRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRole(String role) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipals(), role);
    }
    
    public void checkRoles(String... roleIdentifiers) throws AuthorizationException {
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        clearRunAsIdentities();
        Subject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        String host = null;

        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject) subject;
            //we have to do this in case there are assumed identities - we don't want to lose the 'real' principals:
            principals = delegating.principals;
            host = delegating.host;
        } else {
            principals = subject.getPrincipals();
        }

        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.authenticated = true;
        if (token instanceof HostAuthenticationToken) {
            host = ((HostAuthenticationToken) token).getHost();
        }
        if (host != null) {
            this.host = host;
        }
        Session session = subject.getSession(false);
        if (session != null) {
            this.session = decorate(session);
            this.runAsPrincipals = getRunAsPrincipals(this.session);
        } else {
            this.session = null;
        }
        ThreadContext.bind(this);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public boolean isRemembered() {
        PrincipalCollection principals = getPrincipals();
        return principals != null && !principals.isEmpty() && !isAuthenticated();
    }

    public Session getSession() {
        return getSession(true);
    }

    public Session getSession(boolean create) {
        if (log.isTraceEnabled()) {
            log.trace("attempting to get session; create = " + create + "; session is null = " + (this.session == null) + "; session has id = " + (this.session != null && session.getId() != null));
        }

        if (this.session == null && create) {
            log.trace("Starting session for host {}", getHost());
            SessionContext sessionContext = createSessionContext();
            Session session = this.securityManager.start(sessionContext);
            this.session = decorate(session);
        }
        return this.session;
    }

    protected SessionContext createSessionContext() {
        SessionContext sessionContext = new DefaultSessionContext();
        if (StringUtils.hasText(host)) {
            sessionContext.setHost(host);
        }
        return sessionContext;
    }

    public void logout() {
        try {
            clearRunAsIdentities();
            this.securityManager.logout(this);
        } finally {
            this.session = null;
            this.principals = null;
            this.authenticated = false;
            this.runAsPrincipals = null;
            //Don't set securityManager to null here - the Subject can still be
            //used, it is just considered anonymous at this point.  The SecurityManager instance is
            //necessary if the subject would log in again or acquire a new session.  This is in response to
            //https://issues.apache.org/jira/browse/JSEC-22
            //this.securityManager = null;
        }
    }

    private void sessionStopped() {
        this.session = null;
    }

    public <V> V execute(Callable<V> callable) throws ExecutionException {
        Callable<V> associated = associateWith(callable);
        try {
            return associated.call();
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }

    public void execute(Runnable runnable) {
        Runnable associated = associateWith(runnable);
        associated.run();
    }

    public <V> Callable<V> associateWith(Callable<V> callable) {
        return new SubjectCallable<V>(this, callable);
    }

    public Runnable associateWith(Runnable runnable) {
        if (runnable instanceof Thread) {
            String msg = "This implementation does not support Thread arguments because of JDK ThreadLocal " +
                    "inheritance mechanisms required by Shiro.  Instead, the method argument should be a non-Thread " +
                    "Runnable and the return value from this method can then be given to an ExecutorService or " +
                    "another Thread.";
            throw new UnsupportedOperationException(msg);
        }
        return new SubjectRunnable(this, runnable);
    }

    private class StoppingAwareProxiedSession extends ProxiedSession {

        private final DelegatingSubject owner;

        private StoppingAwareProxiedSession(Session target, DelegatingSubject owningSubject) {
            super(target);
            owner = owningSubject;
        }

        public void stop() throws InvalidSessionException {
            super.stop();
            owner.sessionStopped();
        }
    }


    // ======================================
    // 'Run As' support implementations
    // ======================================

    public void runAs(PrincipalCollection principals) {
        if (!hasPrincipals()) {
            String msg = "This subject does not yet have an identity.  Assuming the identity of another " +
                    "Subject is only allowed for Subjects with an existing identity.  Try logging this subject in " +
                    "first, or using the " + Subject.Builder.class.getName() + " to build ad hoc Subject instances " +
                    "with identities as necessary.";
            throw new IllegalStateException(msg);
        }
        pushIdentity(principals);
    }

    public boolean isRunAs() {
        return !CollectionUtils.isEmpty(this.runAsPrincipals);
    }

    public PrincipalCollection getPreviousPrincipals() {
        return isRunAs() ? this.principals : null;
    }

    public PrincipalCollection releaseRunAs() {
        return popIdentity();
    }

    @SuppressWarnings({"unchecked"})
    private List<PrincipalCollection> getRunAsPrincipals(Session session) {
        if (session != null) {
            return (List<PrincipalCollection>) session.getAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
        return null;
    }

    private void clearRunAsIdentities() {
        Session session = getSession(false);
        if (session != null) {
            session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
        this.runAsPrincipals = null;
    }

    private void pushIdentity(PrincipalCollection principals) throws NullPointerException {
        if (CollectionUtils.isEmpty(principals)) {
            String msg = "Specified Subject principals cannot be null or empty for 'run as' functionality.";
            throw new NullPointerException(msg);
        }
        if (this.runAsPrincipals == null) {
            this.runAsPrincipals = new ArrayList<PrincipalCollection>();
        }
        this.runAsPrincipals.add(0, principals);
        Session session = getSession();
        session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, this.runAsPrincipals);
    }

    private PrincipalCollection popIdentity() {
        PrincipalCollection popped = null;
        if (!CollectionUtils.isEmpty(this.runAsPrincipals)) {
            popped = this.runAsPrincipals.remove(0);
            Session session;
            if (!CollectionUtils.isEmpty(this.runAsPrincipals)) {
                //persist the changed deque to the session
                session = getSession();
                session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, this.runAsPrincipals);
            } else {
                //deque is empty, remove it from the session:
                session = getSession(false);
                if (session != null) {
                    session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
                }
            }
        }

        return popped;
    }
}
