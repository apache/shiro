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

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DelegatingSession;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

/**
 * WARNING: THIS IS A WORK IN PROGRESS AND IS NOT RECOMMENDED FOR USE!
 *
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

    private static transient final Logger log = LoggerFactory.getLogger(DelegatingWebSessionManager.class);

    private static final String THREAD_CONTEXT_SESSION_KEY =
            DelegatingWebSessionManager.class.getName() + ".THREAD_CONTEXT_SESSION_KEY";

    private SessionManager delegateSessionManager = null;

    public DelegatingWebSessionManager() {
        setSessionValidationSchedulerEnabled(false);
    }

    public DelegatingWebSessionManager(SessionManager delegateSessionManager) {
        this();
        this.delegateSessionManager = new ThreadClearingSessionManager(delegateSessionManager);
    }

    public void setDelegateSessionManager(SessionManager delegateSessionManager) {
        this.delegateSessionManager = new ThreadClearingSessionManager(delegateSessionManager);
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
    protected Session doCreateSession(SessionContext initData) {
        assertDelegateExists();
        Session session = this.delegateSessionManager.start(initData);
        return new DelegatingSession(this, session.getId());
    }

    @Override
    protected void applyGlobalSessionTimeout(Session session) {
        //do nothing so we don't override the back-end's session settings.
        //TODO - ensure front end session manager settings cannot be altered
    }

    @Override
    protected Session retrieveSessionFromDataSource(Serializable id) throws InvalidSessionException {
        //use thread-local caching to eliminate repeated 'hits' on the back-end data store during
        //the thread execution.  We do this here and not in the parent class since we can ensure the
        //ThreadContext is being cleared at the end of each request due to the ShiroFilter being required in web
        //environments (which automatically clears the thread).
        Session session = (Session) ThreadContext.get(THREAD_CONTEXT_SESSION_KEY);
        if (session != null) {
            log.trace("Returning thread-cached session.");
            return session;
        }
        assertDelegateExists();
        //get the host address and bind it to the thread.  This call will both validate the session as well as
        //make it accessible for futher host checks:
        String host = this.delegateSessionManager.getHost(id);
        session = new DelegatingSession(this.delegateSessionManager, id, host);
        log.trace("Cached the session retrieved from the datasource in a thread-local for continued thread access.");
        ThreadContext.put(THREAD_CONTEXT_SESSION_KEY, session);

        return session;
    }

    protected void removeThreadBoundSession() {
        log.debug("Session is invalid or an invalid id was encountered.  Unbinding the thread-cached session.");
        ThreadContext.remove(THREAD_CONTEXT_SESSION_KEY);
    }

    @Override
    protected void onChange(Session session) {
        //do nothing - back-end will react to change as appropriate
    }

    @Override
    protected void doValidate(Session session) throws InvalidSessionException {
        //do nothing - we rely on lazy session exceptions and recreation via the SessionManagerProxy to avoid
        //costly validation checks on each session access.
    }


    private interface SessionManagerCallback {
        Object doWithSessionManager(SessionManager sm) throws SessionException;
    }

    private class ThreadClearingSessionManager implements SessionManager {

        private final SessionManager target;

        private ThreadClearingSessionManager(SessionManager target) {
            this.target = target;
        }

        private Object execute(SessionManagerCallback smc) throws SessionException {
            try {
                return smc.doWithSessionManager(target);
            } catch (SessionException se) {
                removeThreadBoundSession();
                //propagate after cleanup:
                throw se;
            }
        }

        public Session start(final SessionContext initData) throws AuthorizationException {
            return (Session) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.start(initData);
                }
            });
        }

        public Date getStartTimestamp(final Serializable sessionId) {
            return (Date) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getStartTimestamp(sessionId);
                }
            });
        }

        public Date getLastAccessTime(final Serializable sessionId) {
            return (Date) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getLastAccessTime(sessionId);
                }
            });
        }

        public boolean isValid(final Serializable sessionId) {
            return (Boolean) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.isValid(sessionId);
                }
            });
        }

        public void checkValid(final Serializable sessionId) throws InvalidSessionException {
            execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    sm.checkValid(sessionId);
                    return null;
                }
            });
        }

        public long getTimeout(final Serializable sessionId) throws InvalidSessionException {
            return (Long) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getTimeout(sessionId);
                }
            });
        }

        public void setTimeout(final Serializable sessionId, final long maxIdleTimeInMillis) throws InvalidSessionException {
            execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    sm.setTimeout(sessionId, maxIdleTimeInMillis);
                    return null;
                }
            });
        }

        public void touch(final Serializable sessionId) throws InvalidSessionException {
            execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    sm.touch(sessionId);
                    return null;
                }
            });
        }

        public String getHost(final Serializable sessionId) {
            return (String) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getHost(sessionId);
                }
            });
        }

        public void stop(final Serializable sessionId) throws InvalidSessionException {
            execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    sm.stop(sessionId);
                    return null;
                }
            });
        }

        @SuppressWarnings({"unchecked"})
        public Collection<Object> getAttributeKeys(final Serializable sessionId) {
            return (Collection<Object>) execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getAttributeKeys(sessionId);
                }
            });
        }

        public Object getAttribute(final Serializable sessionId, final Object key) throws InvalidSessionException {
            return execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.getAttribute(sessionId, key);
                }
            });
        }

        public void setAttribute(final Serializable sessionId, final Object key, final Object value) throws InvalidSessionException {
            execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    sm.setAttribute(sessionId, key, value);
                    return null;
                }
            });
        }

        public Object removeAttribute(final Serializable sessionId, final Object key) throws InvalidSessionException {
            return execute(new SessionManagerCallback() {
                public Object doWithSessionManager(SessionManager sm) throws SessionException {
                    return sm.removeAttribute(sessionId, key);
                }
            });
        }
    }
}
