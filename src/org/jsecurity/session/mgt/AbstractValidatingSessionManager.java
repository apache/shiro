/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.session.mgt;

import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Date;

/**
 * Default business-tier implementation of the {@link ValidatingSessionManager} interface.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public abstract class AbstractValidatingSessionManager extends AbstractSessionManager
        implements ValidatingSessionManager {

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    private static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;

    /** Default global session timeout value (30 * 60 * 1000 milliseconds = 30 minutes). */
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

    public void setSessionValidationScheduler( SessionValidationScheduler sessionValidationScheduler ) {
        this.sessionValidationScheduler = sessionValidationScheduler;
    }

    public SessionValidationScheduler getSessionValidationScheduler() {
        return sessionValidationScheduler;
    }

    /**
     * Returns the time in milliseconds that any session may remain idle before expiring.  This
     * value is just a global default for all sessions and may be overridden by subclasses on a
     * <em>per-session</em> basis by overriding the {@link #getTimeout(Session)} method if
     * so desired.
     *
     * <ul>
     *     <li>A negative return value means sessions never expire.</li>
     *     <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
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
     * value is just a global default for all sessions.  Subclasses may override the
     * {@link #getTimeout} method to determine time-out values on a <em>per-session</em> basis.
     *
     * @param globalSessionTimeout the time in milliseconds any session may remain idle before
     * expiring.
     */
    public void setGlobalSessionTimeout( int globalSessionTimeout ) {
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
     * @param sessionValidationInterval the time in milliseconds between checking for valid sessions to reap orphans.
     */
    public void setSessionValidationInterval( long sessionValidationInterval ) {
        this.sessionValidationInterval = sessionValidationInterval;
    }

    public long getSessionValidationInterval() {
        return sessionValidationInterval;
    }

    protected void validate(Session session) throws InvalidSessionException {

        if (isExpired(session)) {
            //update EIS entry if it hasn't been updated already:
            if (!session.isExpired()) {
                expire(session);
            }

            //throw an exception explaining details of why it expired:
            Date lastAccessTime = session.getLastAccessTime();
            long timeout = getTimeout(session);

            Serializable sessionId = session.getId();

            DateFormat df = DateFormat.getInstance();
            String msg = "Session with id [" + sessionId + "] has expired. " +
                    "Last access time: " + df.format(lastAccessTime) +
                    ".  Current time: " + df.format(new Date()) +
                    ".  Session timeout is set to " + timeout / MILLIS_PER_SECOND + " seconds (" +
                    timeout / MILLIS_PER_MINUTE + " minutes)";
            if (log.isTraceEnabled()) {
                log.trace(msg);
            }
            throw new ExpiredSessionException(msg, sessionId);
        }

        //check for stopped (but not expired):
        if (session.getStopTimestamp() != null) {
            //destroy timestamp is set, so the session is considered stopped:
            String msg = "Session with id [" + session.getId() + "] has been " +
                    "explicitly stopped.  No further interaction under this session is " +
                    "allowed.";
            throw new InvalidSessionException(msg, session.getId());
        }
    }

    /**
     * Determines if the specified session is expired.
     *
     * @param session the persistent pojo Session implementation to check for expiration.
     * @return true if the specified session has expired, false otherwise.
     */
    protected boolean isExpired(Session session) {

        //If the EIS data has already been set as expired, return true:

        //WARNING:  This will cause an infinite loop if the session argument is a proxy back
        //to this instance (e.g. as would be the case if passing in a DelegatingSession instace.
        //To be safe, make sure the argument is representative of EIS data and
        //the isExpired method returns a boolean class attribute and does not call another object.
        if (session.isExpired()) {
            return true;
        }

        if (isExpirationEnabled(session)) {

            long timeout = getTimeout(session);

            if (timeout >= 0l) {

                Date lastAccessTime = session.getLastAccessTime();

                if (lastAccessTime == null) {
                    String msg = "session.lastAccessTime for session with id [" +
                            session.getId() + "] is null.  This value must be set at " +
                            "least once.  Please check the " +
                            session.getClass().getName() + " implementation and ensure " +
                            "this value will be set (perhaps in the constructor?)";
                    throw new IllegalStateException(msg);
                }

                // Calculate at what time a session would have been last accessed
                // for it to be expired at this point.  In other words, subtract
                // from the current time the amount of time that a session can
                // be inactive before expiring.  If the session was last accessed
                // before this time, it is expired.
                long expireTimeMillis = System.currentTimeMillis() - timeout;
                Date expireTime = new Date(expireTimeMillis);
                return lastAccessTime.before(expireTime);
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("No timeout for session with id [" + session.getId() +
                            "].  Session is not considered expired.");
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Time-out is disabled for Session with id [" + session.getId() +
                        "].  Session is not expired.");
            }
        }

        return false;
    }

    /**
     * Returns whether or not a particular session can expire.
     *
     * <p>Default implementation always returns <tt>true</tt>.
     *
     * <p>Overriding this method can be particularly useful in some circumstances.  For example,
     * daemon users (background process users) can be configured in a system like any other user.
     * It is much easier to define a daemon account and use the same session and security framework
     * that supports normal human users, rather than program special-case logic.  Daemon accounts
     * are often expected to interact with the system at any time, regardless of (in)activity.
     * This method provides a means to disable session expiration in such cases.
     *
     * <p>Most overriding implementations usually infer a user or user id from the specified
     * <tt>Session</tt> and determine per-user timeout settings in a specific manner.
     *
     * @param session the session for which to determine if timeout expiration is enabled.
     * @return true if expiration is enabled for the specified session, false otherwise.
     */
    protected boolean isExpirationEnabled(Session session) {
        return getTimeout(session) >= 0l;
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

        if ( log.isDebugEnabled() ) {
            log.debug( "No sessionValidationScheduler set.  Attempting to create default instance." );
        }
        scheduler = new ExecutorServiceSessionValidationScheduler( this );
        ((ExecutorServiceSessionValidationScheduler)scheduler).setInterval(getSessionValidationInterval());
        if ( log.isTraceEnabled() ) {
            log.trace( "Created default SessionValidationScheduler instance of type [" + scheduler.getClass().getName() + "]." );
        }
        return scheduler;
    }

    protected void startSessionValidation() {
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if ( scheduler == null ) {
            scheduler = createSessionValidationScheduler();
            setSessionValidationScheduler( scheduler );
        }
        if ( log.isInfoEnabled() ) {
            log.info( "Starting session validation scheduler..." );
        }
        scheduler.startSessionValidation();
    }

    protected void stopSessionValidation() {
        SessionValidationScheduler scheduler = getSessionValidationScheduler();
        if ( scheduler != null ) {
            try {
                scheduler.stopSessionValidation();
            } catch ( Exception e ) {
                if ( log.isDebugEnabled() ) {
                    String msg = "Unable to stop SessionValidationScheduler.  Ignoring (shutting down)...";
                    log.debug( msg, e );
                }
            }
            LifecycleUtils.destroy(scheduler);
            setSessionValidationScheduler(null);
        }
    }

    public void init() {
        if (isSessionValidationSchedulerEnabled()) {
            startSessionValidation();
        }
        afterSessionValidationStarted();
    }

    protected void afterSessionValidationStarted(){}

    public void destroy() {
        beforeSessionValidationStopped();
        stopSessionValidation();
    }

    protected void beforeSessionValidationStopped(){}


    /**
     * @see ValidatingSessionManager#validateSessions()
     */
    public void validateSessions() {
        if ( log.isInfoEnabled() ) {
            log.info( "Validating all active sessions..." );
        }

        int invalidCount = 0;

        Collection<Session> activeSessions = getActiveSessions();

        if ( activeSessions != null && !activeSessions.isEmpty() ) {
            for ( Session s : activeSessions ) {
                try {
                    validate( s );
                } catch ( InvalidSessionException e ) {
                    if ( log.isDebugEnabled() ) {
                        boolean expired = ( e instanceof ExpiredSessionException );
                        String msg = "Invalidated session with id [" + s.getId() + "]" +
                            ( expired ? " (expired)" : " (stopped)" );
                        log.debug( msg );
                    }
                    invalidCount++;
                }
            }
        }

        if ( log.isInfoEnabled() ) {
            String msg = "Finished session validation.";
            if ( invalidCount > 0 ) {
                msg += "  [" + invalidCount + "] sessions were stopped.";
            } else {
                msg += "  No sessions were stopped.";
            }
            log.info( msg );
        }
    }

    protected abstract Collection<Session> getActiveSessions();

    public void validateSession( Serializable sessionId ) {
        //standard getSession call will validate, so just call the method:
        getSession(sessionId);
    }

}
