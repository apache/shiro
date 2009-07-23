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
package org.apache.shiro.web;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.session.DelegatingWebSessionManager;
import org.apache.shiro.web.session.WebSessionManager;

/**
 * A {@code DelegatingWebSecurityManager} performs all normal web-related operations of the superclass
 * {@link DefaultWebSecurityManager} (handling cookies, HTTP requests, and other similar tasks), but delegates all of
 * its authentication, authorization and session operations to a delegate {@link SecurityManager SecurityManager}
 * instance.
 * <p/>
 * The {@code DelegatingWebSecurityManager} plays a part in some enterprise environments where the web tier and
 * business-logic tier do not reside in the same virtual machine.  In these environments, this component performs all
 * standard Web/Http security operations, but delegates the 'real' authentication, authorization and session management
 * operations to a wrapped {@code SecurityManager} instance responsible for those operations.  Usually the wrapped
 * {@code SecurityManager} instance is a remoting proxy that communicates with a remote/back-end {@code SecurityManager}
 * that is responsible for the 'real' security duties.
 * <p/>
 * In such distributed environments, all components in the web-tier VM use the {@link DelegatingWebSecurityManager}
 * instance as if it were the normal primary {@code SecurityManager} and are unaware of the distributed nature of the
 * application's configuration.
 *
 * @since 1.0
 */
public class DelegatingWebSecurityManager extends DefaultWebSecurityManager {

    public DelegatingWebSecurityManager() {
        super();
        //disable caching for now (delegate SecurityManager should cache if necessary):
        setCacheManager(null);
        //default to native sessions, since http sessions hosted in a web server would not
        //be accessible to a back-end SecurityManager and native Sessions are:
        setSessionMode(DefaultWebSecurityManager.NATIVE_SESSION_MODE);
    }

    public DelegatingWebSecurityManager(SecurityManager delegate) {
        this();
        setDelegateSecurityManager(delegate);
    }

    /**
     * Receives the target/delegate {@link SecurityManager SecurityManager} instance, often a
     * {@code SecurityManager} remoting proxy in distributed/federated environments.
     * <p/>
     * This implementation immediately sets this instance as the
     * {@link #setAuthenticator(org.apache.shiro.authc.Authenticator) delegate authenticator} and
     * {@link #setAuthorizer(org.apache.shiro.authz.Authorizer) delegate authorizer}.  It then constructs a
     * wrapping {@link WebSessionManager WebSubjectFactory} based on the delegate {@code SecurityManager} instance
     * and uses them as this component's
     * {@link #setSessionManager(org.apache.shiro.session.mgt.SessionManager) sessionManager} instance.
     *
     * @param delegate the {@link SecurityManager} to which all authentication, authorization, and
     *                 session management operations will be delegated.
     * @see #createWebSessionManager(org.apache.shiro.mgt.SecurityManager)
     */
    public void setDelegateSecurityManager(SecurityManager delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("sessionManager cannot be null");
        }

        setAuthenticator(delegate);
        setAuthorizer(delegate);

        WebSessionManager sessionManager = createWebSessionManager(delegate);
        setSessionManager(sessionManager);
    }

    /**
     * Creates a WebSessionManager that will be used for all Session operations based on the specified
     * {@code SecurityManager} delegate.  This implementation returns a new {@link DelegatingWebSessionManager} instance.
     *
     * @param delegate the delegate {@code SecurityManager} instance to use for all session operations.
     * @return a WebSessionManager to use for all session operations for this {@link SecurityManager} instance.
     * @see #setSessionManager(org.apache.shiro.session.mgt.SessionManager)
     */
    protected WebSessionManager createWebSessionManager(SecurityManager delegate) {
        return new DelegatingWebSessionManager(delegate);
    }
}
