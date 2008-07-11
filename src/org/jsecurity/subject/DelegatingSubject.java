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
package org.jsecurity.subject;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.InetAuthenticationToken;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthenticatedException;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;

/**
 * <p>Implementation of the <tt>Subject</tt> interface that delegates
 * method calls to an underlying {@link org.jsecurity.mgt.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a <tt>SecurityManager</tt> proxy.</p>
 *
 * <p>This implementation does not maintain state such as roles and permissions (only a subject
 * identifier, such as a user primary key or username) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>SecurityManager</tt> every time to perform
 * the authorization check.</p>
 *
 * <p>A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>SecurityManager</tt> instance.  If caching of authorization
 * data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying <tt>SecurityManager</tt> implementation manage caching, not this class.  A
 * <tt>SecurityManager</tt> is considered a business-tier component, where caching strategies are better suited.</p>
 *
 * <p>Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.</p>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class DelegatingSubject implements Subject {

    protected transient final Logger log = LoggerFactory.getLogger(getClass());

    protected PrincipalCollection principals = new SimplePrincipalCollection();
    protected boolean authenticated = false;
    protected InetAddress inetAddress = null;
    protected Session session = null;
    protected boolean invalidated = false;

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
        this.session = session;
    }

    protected void assertValid() throws InvalidSubjectException {
        if (isInvalidated()) {
            String msg = "The Subject has been invalidated.  It can no longer be used.";
            throw new InvalidSubjectException(msg);
        }
    }

    protected boolean isInvalidated() {
        return invalidated;
    }

    protected void setInvalidated(boolean invalidated) {
        this.invalidated = invalidated;
    }

    public org.jsecurity.mgt.SecurityManager getSecurityManager() {
        return securityManager;
    }

    protected boolean hasPrincipal() {
        return getPrincipal() != null;
    }

    /**
     * Returns the InetAddress associated with the client who created/is interacting with this Subject.
     *
     * @return the InetAddress associated with the client who created/is interacting with this Subject.
     */
    public InetAddress getInetAddress() {
        assertValid();
        return this.inetAddress;
    }

    /**
     * @see Subject#getPrincipal()
     */
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
        assertValid();
        return hasPrincipal() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean isPermitted(Permission permission) {
        assertValid();
        return hasPrincipal() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean[] isPermitted(String... permissions) {
        assertValid();
        if (hasPrincipal()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.length];
        }
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        assertValid();
        if (hasPrincipal()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean isPermittedAll(String... permissions) {
        assertValid();
        return hasPrincipal() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        assertValid();
        return hasPrincipal() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipal()) {
            String msg = "Account data has not yet been associated with this Subject instance" +
                    "(this can be done by executing " + Subject.class.getName() + ".login(AuthenticationToken) )." +
                    "Therefore, authorization operations are not possible (a Subject/Account identity is required first).  " +
                    "Denying authorization.";
            throw new UnauthenticatedException(msg);
        }
    }

    public void checkPermission(String permission) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermissions(String... permissions)
            throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public void checkPermissions(Collection<Permission> permissions)
            throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public boolean hasRole(String roleIdentifier) {
        assertValid();
        return hasPrincipal() && securityManager.hasRole(getPrincipals(), roleIdentifier);
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        assertValid();
        if (hasPrincipal()) {
            return securityManager.hasRoles(getPrincipals(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        assertValid();
        return hasPrincipal() && securityManager.hasAllRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRole(String role) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipals(), role);
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertValid();
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        assertValid();
        Subject authcSecCtx = securityManager.login(token);
        PrincipalCollection principals = authcSecCtx.getPrincipals();
        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null, and if a collection, the collection must " +
                    "be populated with one or more elements.  Please check the SecurityManager " +
                    "implementation to ensure this happens after a successful login attempt.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.session = authcSecCtx.getSession(false);
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
        assertValid();
        return authenticated;
    }

    public Session getSession() {
        return getSession(true);
    }

    public Session getSession(boolean create) {
        assertValid();

        if (log.isTraceEnabled()) {
            log.trace("attempting to get session; create = " + create + "; session is null = " + (this.session == null) + "; session has id = " + (this.session != null && session.getId() != null));
        }

        if (this.session == null && create) {


            if (log.isTraceEnabled()) {
                log.trace("starting session for address [" + getInetAddress() + "]");
            }

            this.session = securityManager.start(getInetAddress());
        }
        return this.session;
    }

    public void logout() {
        if (isInvalidated()) {
            return;
        }

        try {
            this.securityManager.logout(getPrincipals());
        } finally {
            setInvalidated(true);
            this.session = null;
            this.principals = null;
            this.authenticated = false;
            this.inetAddress = null;
            this.securityManager = null;
        }
    }

}
