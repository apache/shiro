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
package org.jsecurity.session.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;

/**
 * Default business-tier implementation of the {@link ValidatingSessionManager} interface.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public abstract class AbstractValidatingSessionManager extends AbstractSessionManager
        implements ValidatingSessionManager, Destroyable {

    private static final Log log = LogFactory.getLog(AbstractValidatingSessionManager.class);

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    protected static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;

    /**
     * Default main session timeout value (30 * 60 * 1000 milliseconds = 30 minutes).
     */
    public static final long DEFAULT_GLOBAL_SESSION_TIMEOUT = 30 * MILLIS_PER_MINUTE;

    /**
     * The default interval at which sessions will be validated (1 hour);
     * This can be overridden by calling {@link #setSessionValidationInterval(long)}
     */
    public static final long DEFAULT_SESSION_VALIDATION_INTERVAL = MILLIS_PER_HOUR;

    protected boolean sessionValidationSchedulerEnabled = true; //default
    /**
     * Scheduler used to validate sessions on a regular basis.
     */
    protected SessionValidationScheduler sessionValidationScheduler = null;

    protected long sessionValidationInterval = DEFAULT_SESSION_VALIDATION_INTERVAL;
    protected long globalSessionTimeout = DEFAULT_GLOBAL_SESSION_TIMEOUT;

    public AbstractValidatingSessionManager() {
    }

    public boolean isSessionValidationSchedulerEnabled() {
        return sessionValidationSchedulerEnabled;
    }

    public void setSessionValidationSchedulerEnabled(boolean sessionValidationSchedulerEnabled) {
        this.sessionValidationSchedulerEnabled = sessionValidationSchedulerEnabled;
    }

    public void setSessionValidationScheduler(SessionValidationScheduler sessionValidationScheduler) {
        this.sessionValidationScheduler = sessionValidationScheduler;
    }

    public SessionValidationScheduler getSessionValidationScheduler() {
        return sessionValidationScheduler;
    }

    public void startSessionValidationIfNecessary() {
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if (isSessionValidationSchedulerEnabled() && (scheduler == null || !scheduler.isRunning())) {
            startSessionValidation();
        }
    }

    /**
     * Returns the time in milliseconds that any session may remain idle before expiring.  This
     * value is just a main default for all sessions and may be overridden by subclasses on a
     * <em>per-session</em> basis by overriding the {@link #getTimeout(Session)} method if
     * so desired.
     *
     * <ul>
     * <li>A negative return value means sessions never expire.</li>
     * <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
     * </ul>
     *
     * <p>Unless overridden via the {@link #setGlobalSessionTimeout} method, the default value is
     * {@link #DEFAULT_GLOBAL_SESSION_TIMEOUT}.
     *
     * @return the time in milliseconds that any session may remain idle before expiring.
     */
    public long getGlobalSessionTimeout() {
        return globalSessionTimeout;
    }

    /**
     * Sets the time in milliseconds that any session may remain idle before expiring.  This
     * value is just a main default for all sessions.  Subclasses may override the
     * {@link #getTimeout} method to determine time-out values on a <em>per-session</em> basis.
     *
     * @param globalSessionTimeout the time in milliseconds any session may remain idle before
     *                             expiring.
     */
    public void setGlobalSessionTimeout(int globalSessionTimeout) {
        this.globalSessionTimeout = globalSessionTimeout;
    }

    /**
     * If using the underlying default <tt>SessionValidationScheduler</tt> (that is, the
     * {@link #setSessionValidationScheduler(SessionValidationScheduler) setSessionValidationScheduler} method is
     * never called) , this method allows one to specify how
     * frequently session should be validated (to check for orphans).  The default value is
     * {@link #DEFAULT_SESSION_VALIDATION_INTERVAL}.
     *
     * <p>If you override the default scheduler, it is assumed that overriding instance 'knows' how often to
     * validate sessions, and this attribute will be ignored.
     *
     * <p>Unless this method is called, the default value is {@link #DEFAULT_SESSION_VALIDATION_INTERVAL}.
     *
     * @param sessionValidationInterval the time in milliseconds between checking for valid sessions to reap orphans.
     */
    public void setSessionValidationInterval(long sessionValidationInterval) {
        this.sessionValidationInterval = sessionValidationInterval;
    }

    public long getSessionValidationInterval() {
        return sessionValidationInterval;
    }

    protected final Session doGetSession(Serializable sessionId) throws InvalidSessionException {
        startSessionValidationIfNecessary();
        return retrieveSession(sessionId);
    }

    protected abstract Session retrieveSession(Serializable sessionId) throws InvalidSessionException;

    protected final Session createSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        startSessionValidationIfNecessary();
        return doCreateSession(originatingHost);
    }

    protected abstract Session doCreateSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException;

    protected void validate(Session session) throws InvalidSessionException {
        if (session instanceof ValidatingSession) {
            try {
                ((ValidatingSession) session).validate();
            } catch (ExpiredSessionException ese) {
                notifyExpiration(session);
                onExpiration(session);
                //propagate to caller:
                throw ese;
            }
        } else {
            String msg = "The " + getClass().getName() + " implementation only supports validating " +
                    "Session implementations of the " + ValidatingSession.class.getName() + " interface.  " +
                    "Please either implement this interface in your session implementation or override the " +
                    getClass().getName() + ".validate(Session) method to perform validation.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Subclass template hook in case per-session timeout is not based on
     * {@link org.jsecurity.session.Session#getTimeout()}.
     *
     * <p>This implementation merely returns {@link org.jsecurity.session.Session#getTimeout()}</p>
     *
     * @param session the session for which to determine session timeout.
     * @return the time in milliseconds the specified session may remain idle before expiring.
     */
    protected long getTimeout(Session session) {
        return session.getTimeout();
    }

    protected SessionValidationScheduler createSessionValidationScheduler() {
        SessionValidationScheduler scheduler;

        if (log.isDebugEnabled()) {
            log.debug("No sessionValidationScheduler set.  Attempting to create default instance.");
        }
        scheduler = new ExecutorServiceSessionValidationScheduler(this);
        ((ExecutorServiceSessionValidationScheduler) scheduler).setInterval(getSessionValidationInterval());
        if (log.isTraceEnabled()) {
            log.trace("Created default SessionValidationScheduler instance of type [" + scheduler.getClass().getName() + "].");
        }
        return scheduler;
    }

    protected void startSessionValidation() {
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if (scheduler == null) {
            scheduler = createSessionValidationScheduler();
            setSessionValidationScheduler(scheduler);
        }
        if (log.isInfoEnabled()) {
            log.info("Starting session validation scheduler...");
        }
        scheduler.startSessionValidation();
        afterSessionValidationStarted();
    }

    protected void afterSessionValidationStarted() {
    }

    protected void stopSessionValidation() {
        beforeSessionValidationStopped();
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if (scheduler != null) {
            try {
                scheduler.stopSessionValidation();
                if (log.isInfoEnabled()) {
                    log.info("Stopped session validation scheduler.");
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to stop SessionValidationScheduler.  Ignoring (shutting down)...";
                    log.debug(msg, e);
                }
            }
            LifecycleUtils.destroy(scheduler);
            setSessionValidationScheduler(null);
        }
    }

    protected void beforeSessionValidationStopped() {
    }

    public void destroy() {
        stopSessionValidation();
    }

    /**
     * @see ValidatingSessionManager#validateSessions()
     */
    public void validateSessions() {
        if (log.isInfoEnabled()) {
            log.info("Validating all active sessions...");
        }

        int invalidCount = 0;

        Collection<Session> activeSessions = getActiveSessions();

        if (activeSessions != null && !activeSessions.isEmpty()) {
            for (Session s : activeSessions) {
                try {
                    validate(s);
                } catch (InvalidSessionException e) {
                    if (log.isDebugEnabled()) {
                        boolean expired = (e instanceof ExpiredSessionException);
                        String msg = "Invalidated session with id [" + s.getId() + "]" +
                                (expired ? " (expired)" : " (stopped)");
                        log.debug(msg);
                    }
                    invalidCount++;
                }
            }
        }

        if (log.isInfoEnabled()) {
            String msg = "Finished session validation.";
            if (invalidCount > 0) {
                msg += "  [" + invalidCount + "] sessions were stopped.";
            } else {
                msg += "  No sessions were stopped.";
            }
            log.info(msg);
        }
    }

    protected abstract Collection<Session> getActiveSessions();

    public void validateSession(Serializable sessionId) {
        //standard getSession call will validate, so just call the method:
        getSession(sessionId);
    }

}
