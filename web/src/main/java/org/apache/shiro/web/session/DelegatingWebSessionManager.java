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
package org.apache.shiro.web.session;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DelegatingSession;
import org.apache.shiro.session.mgt.SessionManager;

import java.io.Serializable;
import java.util.Map;

/**
 * A {@code DelegatingWebSessionManager} performs all normal operations of the superclass {@link DefaultWebSessionManager}
 * except it does not perform {@code Session} creation or lookup duties itself and instead delegates those duties
 * to a target/wrapped {@link SessionManager SessionManager} instance.  It is primarily used to support
 * the functionality of the {@link org.apache.shiro.web.DelegatingWebSecurityManager DelegatingWebSecurityManager} and
 * for the most part is considered an infrastructural component that would rarely need to be referenced by Shiro users.
 * <p/>
 * The {@code DelegatingWebSessionManager} plays a part in some enterprise environments where the web tier and
 * business-logic tier do not reside in the same virtual machine.  In these environments, this component performs all
 * standard Web/Http session operations, but delegates {@code Session} creation and lookup to a wrapped
 * {@code SessionManager} instance responsible for those operations.  Usually the wrapped {@code SessionManager}
 * instance is a remoting proxy that communicates with a remote/back-end SessionManager that is responsible for the
 * 'real' creation/lookup duties.
 *
 * @since 1.0
 */
public class DelegatingWebSessionManager extends DefaultWebSessionManager {

    private static final String THREAD_CONTEXT_SESSION_KEY =
            DelegatingWebSessionManager.class.getName() + ".THREAD_CONTEXT_SESSION_KEY";

    private SessionManager delegateSessionManager = null;

    public DelegatingWebSessionManager() {
        setSessionValidationSchedulerEnabled(false);
    }

    public DelegatingWebSessionManager(SessionManager delegateSessionManager) {
        this();
        this.delegateSessionManager = delegateSessionManager;
    }

    public void setDelegateSessionManager(SessionManager delegateSessionManager) {
        this.delegateSessionManager = delegateSessionManager;
    }

    private void assertDelegateExists() {
        //can only be null in a Dependency Injection environment, so check to ensure it is not null:
        if (this.delegateSessionManager == null) {
            throw new IllegalStateException("delegateSessionManager property has not been set.  Please check your " +
                    "configuration to ensure the " + getClass().getName() + " instance has been injected with a " +
                    SessionManager.class.getName() + " delegate instance.");
        }
    }

    /**
     * Can be used in DI environments to ensure the
     * {@link #setDelegateSessionManager(org.apache.shiro.session.mgt.SessionManager) delegateSessionManager} exists and
     * has been set correctly.
     *
     * @throws IllegalStateException if the {@code delegateSessionManager} property has not been set.
     */
    public void init() throws IllegalStateException {
        assertDelegateExists();
    }

    @Override
    protected Session doCreateSession(Map initData) {
        assertDelegateExists();
        Serializable sessionId = this.delegateSessionManager.start(initData);
        return new DelegatingSession(this, sessionId);
    }

    @Override
    protected void applyGlobalSessionTimeout(Session session) {
        //do nothing so we don't override the back-end's session settings.
        //TODO - ensure front end session manager settings cannot be altered
    }

    @Override
    protected Session retrieveSessionFromDataSource(Serializable id) throws InvalidSessionException {
        /*Session session = (Session)ThreadContext.get(THREAD_CONTEXT_SESSION_KEY);
        if ( session != null ) {
            return session;
        }*/
        assertDelegateExists();
        this.delegateSessionManager.checkValid(id);
        return new DelegatingSession(this.delegateSessionManager, id);
        /*//we need the DelegatingSession to reference the delegateSessionManager and not 'this' so
        //we avoid an infinite loop:
        session = new DelegatingSession(this.delegateSessionManager, id);
        ThreadContext.put(THREAD_CONTEXT_SESSION_KEY, session);
        
        return session;*/
    }

    @Override
    protected void onChange(Session session) {
        //do nothing - back-end will react to change as appropriate
    }

    @Override
    protected void doValidate(Session session) throws InvalidSessionException {
        /*if ( session == null ) {
            throw new InvalidSessionException("Session method argument is null!" );
        }
        Serializable id = session.getId();
        if ( id == null ) {
            throw new InvalidSessionException("Session does not have an id!" );
        }
        assertDelegateExists();
        this.delegateSessionManager.checkValid(id);*/
    }
}
