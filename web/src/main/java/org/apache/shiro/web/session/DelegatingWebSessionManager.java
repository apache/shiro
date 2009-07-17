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
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;

import java.io.Serializable;
import java.net.InetAddress;
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
        InetAddress host = null;
        if (initData != null && initData.containsKey(SessionFactory.ORIGINATING_HOST_KEY)) {
            host = (InetAddress) initData.get(SessionFactory.ORIGINATING_HOST_KEY);
        }
        Serializable sessionId = this.delegateSessionManager.start(host);
        return new DelegatingSession(this, sessionId);
    }

    @Override
    protected Session retrieveSessionFromDataSource(Serializable id) throws InvalidSessionException {
        assertDelegateExists();
        this.delegateSessionManager.checkValid(id);
        //we need the DelegatingSession to reference the delegateSessionManager and not 'this' so
        //we avoid an infinite loop:
        return new DelegatingSession(this.delegateSessionManager, id);
    }

    @Override
    protected void doValidate(Session session) throws InvalidSessionException {
        session.touch();
    }
}
