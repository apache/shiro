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
package org.apache.ki.subject;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.ki.authc.AuthenticationException;
import org.apache.ki.authc.AuthenticationToken;
import org.apache.ki.authc.InetAuthenticationToken;
import org.apache.ki.authz.AuthorizationException;
import org.apache.ki.authz.Permission;
import org.apache.ki.authz.UnauthenticatedException;
import org.apache.ki.mgt.SecurityManager;
import org.apache.ki.session.InvalidSessionException;
import org.apache.ki.session.ProxiedSession;
import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.DelegatingSession;
import org.apache.ki.util.ThreadContext;

/**
 * Implementation of the <tt>Subject</tt> interface that delegates
 * method calls to an underlying {@link org.apache.ki.mgt.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a <tt>SecurityManager</tt> proxy.
 * <p/>
 * This implementation does not maintain state such as roles and permissions (only <code>Subject</code>
 * {@link #getPrincipals() principals}, such as usernames or user primary keys) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>SecurityManager</tt> every time to perform
 * the authorization check.
 * <p/>
 * A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>SecurityManager</tt> instance.  If caching of authorization
 * data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying <tt>SecurityManager</tt> implementation or its delegate components
 * manage caching, not this class.  A <tt>SecurityManager</tt> is considered a business-tier component,
 * where caching strategies are better suited.
 * <p/>
 * Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class DelegatingSubject implements Subject {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DelegatingSubject.class);

    protected PrincipalCollection principals = new SimplePrincipalCollection();
    protected boolean authenticated = false;
    protected InetAddress inetAddress = null;
    protected Session session = null;

    protected SecurityManager securityManager;

    protected static InetAddress getLocalHost() {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public DelegatingSubject(SecurityManager securityManager) {
        this(null, false, getLocalHost(), null, securityManager);
    }

    public DelegatingSubject(PrincipalCollection principals, boolean authenticated, InetAddress inetAddress,
                             Session session, SecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.principals = principals;

        this.authenticated = authenticated;

        if (inetAddress != null) {
            this.inetAddress = inetAddress;
        } else {
            this.inetAddress = getLocalHost();
        }
        if (session != null) {
            this.session = decorate(session);
        }
    }

    protected Session decorate(Session session) {
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        return decorateSession(session.getId());
    }

    protected Session decorateSession(Serializable sessionId) {
        if (sessionId == null) {
            throw new IllegalArgumentException("sessionId cannot be null");
        }
        DelegatingSession target = new DelegatingSession(getSecurityManager(), sessionId);
        return new StoppingAwareProxiedSession(target, this);
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected boolean hasPrincipals() {
        PrincipalCollection pc = getPrincipals();
        return pc != null && !pc.isEmpty();
    }

    /**
     * Returns the InetAddress associated with the client who created/is interacting with this Subject.
     *
     * @return the InetAddress associated with the client who created/is interacting with this Subject.
     */
    public InetAddress getInetAddress() {
        return this.inetAddress;
    }

    /** @see Subject#getPrincipal() */
    public Object getPrincipal() {
        PrincipalCollection principals = getPrincipals();
        if (principals == null || principals.isEmpty()) {
            return null;
        }
        return principals.asSet().iterator().next();
    }

    public PrincipalCollection getPrincipals() {
        return this.principals;
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
            String msg = "Identity principals are not associated with this Subject instance - " +
                    "authorization operations require an identity to check against.  A Subject instance will " +
                    "acquire these identifying principals automatically after a successful login is performed " +
                    "be executing " + Subject.class.getName() + ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled.  This exception can also occur when the current Subject has logged out, " +
                    "which relinquishes its identity and essentially makes it anonymous again.  " +
                    "Because an identity is currently not known due to any of these conditions, " +
                    "authorization is denied.";
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

    public void checkPermissions(String... permissions)
            throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public void checkPermissions(Collection<Permission> permissions)
            throws AuthorizationException {
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

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        Subject subject = securityManager.login(token);
        PrincipalCollection principals = subject.getPrincipals();
        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.  " +
                    "Please check the SecurityManager implementation to ensure this happens after a " +
                    "successful login attempt.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        Session session = subject.getSession(false);
        if (session != null) {
            this.session = decorate(session);
        } else {
            this.session = null;
        }
        this.authenticated = true;
        if (token instanceof InetAuthenticationToken) {
            InetAddress addy = ((InetAuthenticationToken) token).getInetAddress();
            if (addy != null) {
                this.inetAddress = addy;
            }
        }
        ThreadContext.bind(this);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public Session getSession() {
        return getSession(true);
    }

    public Session getSession(boolean create) {
        if (log.isTraceEnabled()) {
            log.trace("attempting to get session; create = " + create + "; session is null = " + (this.session == null) + "; session has id = " + (this.session != null && session.getId() != null));
        }

        if (this.session == null && create) {
            if (log.isTraceEnabled()) {
                log.trace("starting session for address [" + getInetAddress() + "]");
            }
            Serializable sessionId = this.securityManager.start(getInetAddress());
            this.session = decorateSession(sessionId);
        }
        return this.session;
    }

    public void logout() {
        try {
            this.securityManager.logout(getPrincipals());
        } finally {
            this.session = null;
            this.principals = null;
            this.authenticated = false;
            //Don't set securityManager to null here - the Subject can be continued to be
            //used, it is just considered anonymous at this point.  The SecurityManager instance is
            //necessary if the subject would log in again or acquire a new session.  This is in response to
            //https://issues.apache.org/jira/browse/JSEC-22
            //this.securityManager = null;

            //also keep the inetAddress to retain their location:
            //this.inetAddress = null;
        }
    }

    private void sessionStopped() {
        this.session = null;
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

}
