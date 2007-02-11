/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.session.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.*;
import org.jsecurity.session.event.*;
import org.jsecurity.session.support.eis.SessionDAO;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.Principal;
import java.text.DateFormat;
import java.util.Date;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractSessionManager implements SessionManager {

    protected static final int GLOBAL_SESSION_TIMEOUT = 60 * 30; //30 minutes by default;

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SessionDAO sessionDAO = null;
    protected SessionEventSender sessionEventSender = null;
    protected boolean validateHost = true;
    protected Class<? extends Session> sessionClass = null;
    protected int globalSessionTimeout = GLOBAL_SESSION_TIMEOUT;

    public AbstractSessionManager(){}

    public void setSessionDAO( SessionDAO sessionDAO ) {
        this.sessionDAO = sessionDAO;
    }

    public SessionDAO getSessionDAO() {
        return this.sessionDAO;
    }

    /**
     * Sets the {@link org.jsecurity.session.event.SessionEventSender} this Manager will use to send/publish events when
     * a meaningful session event occurs.
     * <p>The instance given can do anything from traditional-style synchronous listener
     * notification to more sophisticated publishing of JMS messages or anything else.
     * @param sessionEventSender the sender to use to propagate session events.
     */
    public void setSessionEventSender( SessionEventSender sessionEventSender ) {
        this.sessionEventSender = sessionEventSender;
    }

    public SessionEventSender getSessionEventSender() {
        return this.sessionEventSender;
    }

    /**
     * Returns the Class that will be used to instantiate new {@link Session} objects when
     * a session starts.
     * @return the Class used to instantiate new {@link Session} objects
     */
    public Class<? extends Session> getSessionClass() {
        return sessionClass;
    }

    /**
     * Sets the class of the {@link Session} implementation to use when instantiating a new
     * session object.  This must be a JavaBeans&reg;-compatible class, with a default,
     * no-argument constructor such that {@link Class#newInstance()} may be invoked.
     * @param sessionClass the Class used to instantiate new {@link Session} objects
     */
    public void setSessionClass( Class<? extends Session> sessionClass ) {
        this.sessionClass = sessionClass;
    }

    /**
     * Returns <tt>true</tt> if this SessionManager will validate the originating host address
     * before creating a session, false otherwise.
     *
     * <p>If <tt>true</tt>, the originating host address will be validated via the
     * {@link #validate(InetAddress)} method.  Subclasses should override that method for
     * application-specific validation.
     *
     * <p>The default implementation always returns <tt>true</tt>
     *
     * @return true if the originating host address will be validated prior to creating a session,
     * false otherwise.
     *
     * @see #validate(InetAddress)
     */
    public boolean isValidateHost() {
        return validateHost;
    }

    /**
     * If set to <tt>true</tt> the <tt>originatingHost</tt> address will be validated prior to
     * starting a new Session.  A value of <tt>false</tt> disables host validation.
     * <p>Defaults to <tt>true</tt>.
     * @param validateHost whether or not to validate the originatingHost address prior to
     * session creation.
     *
     * @see #validate
     * @see #createSession
     */
    public void setValidateHost( boolean validateHost ) {
        this.validateHost = validateHost;
    }

    /**
     * Returns the time in seconds that any session may remain idle before expiring.  This
     * value is just a global default for all sessions and may be overridden by subclasses on a
     * <em>per-session</em> basis by overriding the {@link #getTimeout(Session)} method if
     * so desired.
     *
     * <p>
     *   <ul>
     *     <li>A negative return value means sessions never expire.</li>
     *     <li>A <tt>zero</tt> return value means sessions expire immediately.</li>
     *     <li>A positive return alue indicates normal session timeout will be calculated.</li>
     *   </ul>
     * </p>
     *
     * <p>Unless overridden via the {@link #setGlobalSessionTimeout} method, the default value is
     * 60 * 30 (30 minutes).
     *
     * @return the time in seconds that any session may remain idle before expiring.
     */
    public int getGlobalSessionTimeout() {
        return globalSessionTimeout;
    }

    /**
     * Sets the time in seconds that any session may remain idle before expiring.  This
     * value is just a global default for all sessions.  Subclasses may override the
     * {@link #getTimeout} method to determine time-out values on a <em>per-session</em> basis.
     *
     * @param globalSessionTimeout the time in seconds any session may remain idle before
     * expiring.
     */
    public void setGlobalSessionTimeout( int globalSessionTimeout ) {
        this.globalSessionTimeout = globalSessionTimeout;
    }

    public void init() {
        if ( sessionDAO == null ) {
            String msg = "sessionDAO property has not been set.  The sessionDAO is required to " +
                         "access session objects during runtime.";
            throw new IllegalStateException( msg );
        }
        if ( sessionClass == null ) {
            String msg = "sessionClass property has not been set";
            throw new IllegalStateException( msg );
        }
        if ( sessionEventSender == null ) {
            if ( log.isInfoEnabled() ) {
                String msg = "sessionEventSender property has not been set.  SessionEvents will " +
                             "not be propagated.";
                log.info( msg );
            }
        }
    }

    protected void send( SessionEvent event ) {
        if ( this.sessionEventSender != null ) {
            if ( log.isDebugEnabled() ) {
                String msg = "Using sessionEventSender to send event [" + event + "]";
                log.debug( msg );
            }
            this.sessionEventSender.send( event );
        } else {
            if ( log.isTraceEnabled() ) {
                String msg = "No sessionEventSender set.  Event of type [" +
                             event.getClass().getName() + "] will not be propagated.";
                log.trace( msg );
            }
        }
    }

    /**
     * Ensures the originatingHost is a value allowed by the system for session interaction.
     * Default implementation just ensures the value is not null.  Subclasses may override this
     * method to do any number of checks, such as ensuring the originatingHost is in a valid
     * range, part of a particular subnet, or configured in the database as a valid IP.
     * @param originatingHost the originating host address associated with the session
     * creation attempt.
     */
    protected void validate( InetAddress originatingHost ) throws IllegalArgumentException {
        if ( originatingHost == null ) {
            String msg = "originatingHost argument is null.  A valid non-null originating " +
                         "host address must be specified when initiating a session";
            throw new IllegalArgumentException( msg );
        }
    }

    protected void stop( Session session ) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Stopping session with id [" + session.getSessionId() + "]" );
        }
        onStop( session );
        sessionDAO.update( session );
        send( createStopEvent( session ) );
    }

    /**
     * Subclasses should override this method to update the state of the given
     * {@link Session} implementation prior to updating the EIS with the stopped object.
     * @param session the session object to update w/ data related to being stopped.
     */
    protected void onStop( Session session ){}

    protected void expire( Session session ) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Expiring session with id [" + session.getSessionId() + "]" );
        }
        onExpire( session );
        sessionDAO.update( session );
        send( createExpireEvent( session ) );
    }

    protected SessionEvent createStartEvent( Session session ) {
        return new StartedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createStopEvent( Session session ) {
        return new StoppedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createExpireEvent( Session session ) {
        return new ExpiredSessionEvent( this, session.getSessionId() );
    }

    /**
     * Allows subclasses to update the state of the specified <tt>session</tt> object prior to
     * being saved to the EIS.
     * Default implementation does nothing, since it can't make assumptions about
     * implementations of the interface.
     * @param session the session object to update with data related to be being expired.
     */
    protected void onExpire( Session session ) {}

    protected void validate( Session session ) throws InvalidSessionException {

        if ( isExpired( session ) ) {
            //update EIS entry if it hasn't been updated already:
            if ( !session.isExpired() ) {
                expire( session );
            }

            //throw an exception explaining details of why it expired:
            Date lastAccessTime = session.getLastAccessTime();
            int timeout = getTimeout( session );

            Serializable sessionId = session.getSessionId();

            DateFormat df = DateFormat.getInstance();
            String msg = "Session with id [" + sessionId + "] has expired. " +
                         "Last access time: " + df.format( lastAccessTime ) +
                         ".  Current time: " + df.format( new Date() ) +
                         ".  Session timeout is set to " + timeout + " seconds (" +
                         timeout / 60 + " minutes)";
            if ( log.isTraceEnabled() ) {
                log.trace( msg );
            }
            throw new ExpiredSessionException( msg, sessionId );
        }

        //check for stopped (but not expired):
        if ( session.getStopTimestamp() != null ) {
            //destroy timestamp is set, so the session is considered stopped:
            String msg = "Session with id [" + session.getSessionId() + "] has been " +
                         "explicitly stopped.  No further interaction under this session is " +
                         "allowed.";
            throw new InvalidSessionException( msg, session.getSessionId() );
        }
    }



    protected Session newSessionInstance() {
        try {
            if ( log.isDebugEnabled() ) {
                log.debug( "Instantiating new [" + getSessionClass().getName() + "] instance" );
            }
            return getSessionClass().newInstance();
        } catch ( Exception e ) {
            String msg = "Unable to instantiate an instance of class [" +
                         getSessionClass().getName() + "]";
            throw new SessionException( msg, e );
        }
    }

    /**
     * Subclasses can implement this method to apply properties to the the new session
     * instance created via the {@link #newSessionInstance()} method.
     *
     * <p>Implementations of this method at a minimum would probably want to associate the given host
     * address with the session via an implementation setter method, e.g.
     * <pre>newInstance.setHostAddress( hostAddr );</pre>
     * for session tracking and reporting options.
     *
     * <p>Note that the <tt>hostAddr</tt> parameter may be <tt>null</tt> if
     * {@link #isValidateHost() host validation} is disabled.
     *
     * @param newInstance new instance of the {@link #getSessionClass() sessionClass}
     * @param hostAddr the originating address associated with the session creation - may be
     * <tt>null</tt> if {@link #isValidateHost() host validation} is disabled.
     */
    protected void init( Session newInstance, InetAddress hostAddr ) {}

    protected Session createSession( InetAddress originatingHost ) {

        if ( log.isTraceEnabled() ) {
            log.trace( "Creating session for originating host [" + originatingHost + "]" );
        }

        if ( isValidateHost() ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Host validation enabled.  Validating originating host ["
                           + originatingHost + "]" );
            }
            validate( originatingHost );
        }

        Session s = newSessionInstance();
        if ( log.isDebugEnabled() ) {
            log.debug( "Initializing new Session instance [" + s + "]" );
        }
        init( s, originatingHost );

        //save initialized Session to EIS:
        if ( log.isDebugEnabled() ) {
            log.debug( "Creating new EIS record for new session instance [" + s + "]" );
        }
        sessionDAO.create( s );

        send( createStartEvent( s ) );

        return s;
    }

    protected Session retrieveSession( Serializable sessionId ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Retrieving session with id [" + sessionId + "] from the EIS" );
        }
        Session s = sessionDAO.readSession( sessionId );
        if ( s == null ) {
            String msg = "There is no session in the EIS database with session id [" +
                         sessionId + "]";
            throw new UnknownSessionException( msg );
        }
        return s;
    }

    protected Session retrieveAndValidateSession( Serializable sessionId ) {
        Session s = retrieveSession( sessionId );
        validate( s );
        return s;
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
     */
    protected boolean isExpirationEnabled( Session session ) {
        return true;
    }

    /**
     * Returns the time in seconds the specified session may remain idle before expiring.
     *
     * <p>Most overriding implementations usually infer a user or user id from the specified
     * <tt>Session</tt> and determine per-user timeout values in a specific manner.
     *
     * <p>
     *   <ul>
     *     <li>A negative return value means the session does not time-out/expire.</li>
     *     <li>A <tt>zero</tt> return value means the session should expire immediately (of little value).</li>
     *     <li>A positive return alue indicates normal session timeout will be calculated.</li>
     *   </ul>
     * </p>
     *
     * <p>Default implementation returns the
     * {@link #getGlobalSessionTimeout() global session timeout} for all sessions.
     *
     * @param session the session for which to determine session timeout.
     * @return the time in seconds the specified session may remain idle before expiring.
     */
    protected int getTimeout( Session session ) {
        return getGlobalSessionTimeout();
    }

    /**
     * Determines if the specified session is expired.
     * @param session
     * @return true if the specified session has expired, false otherwise.
     */
    protected boolean isExpired( Session session ) {

        //If the EIS data has already been set as expired, return true:

        //WARNING:  This will cause an infinite loop if the session argument is a proxy back
        //to this instance (e.g. as would be the case if passing in a DelegatingSession instace.
        //To be safe, make sure the argument is representative of EIS data and
        //the isExpired method returns a boolean class attribute and does not call another object.
        if ( session.isExpired() ) {
            return true;
        }

        if ( isExpirationEnabled( session ) ) {

            int timeout = getTimeout( session );

            if ( timeout >= 0 ) {

                Date lastAccessTime = session.getLastAccessTime();

                if ( lastAccessTime == null ) {
                    String msg = "session.lastAccessTime for session with id [" +
                                 session.getSessionId() + "] is null.  This value must be set at " +
                                 "least once.  Please check the " +
                                 session.getClass().getName() + " implementation and ensure " +
                                 "this value will be set (perhaps in the constructor?)";
                    throw new IllegalStateException( msg );
                }

                // Calculate at what time a session would have been last accessed
                // for it to be expired at this point.  In other words, subtract
                // from the current time the amount of time that a session can
                // be inactive before expiring.  If the session was last accessed
                // before this time it is expired.
                long expireTimeMillis = System.currentTimeMillis() - ( 1000 * timeout );
                Date expireTime = new Date( expireTimeMillis );
                return lastAccessTime.before( expireTime );
            } else {
                if ( log.isInfoEnabled() ) {
                    log.info( "No timeout for session with id [" + session.getSessionId() +
                              "].  Session is not considered expired." );
                }
            }
        } else {
            if ( log.isInfoEnabled() ) {
                log.info( "Time-out is disabled for Session with id [" + session.getSessionId() +
                          "].  Session is not expired." );
            }
        }

        return false;
    }

    public Serializable start( InetAddress originatingHost )
        throws HostUnauthorizedException, IllegalArgumentException {
        Session s = createSession( originatingHost );
        return s.getSessionId();
    }

    public Date getStartTimestamp( Serializable sessionId ) {
        return retrieveSession( sessionId ).getStartTimestamp();
    }

    public Date getStopTimestamp( Serializable sessionId ) {
        return retrieveSession( sessionId ).getStopTimestamp();
    }

    public Date getLastAccessTime( Serializable sessionId ) {
        return retrieveSession( sessionId ).getLastAccessTime();
    }

    public boolean isStopped( Serializable sessionId ) {
        return retrieveSession( sessionId ).getStopTimestamp() != null;
    }

    public boolean isExpired( Serializable sessionId ) {
        return retrieveSession( sessionId ).isExpired();
    }

    protected void onTouch( Session session ){}

    public void touch( Serializable sessionId ) throws InvalidSessionException {
        Session s = retrieveAndValidateSession( sessionId );
        onTouch( s );
        sessionDAO.update( s );
    }

    public Principal getPrincipal( Serializable sessionId ) {
        return null;
    }

    public InetAddress getHostAddress( Serializable sessionId ) {
        return retrieveSession( sessionId ).getHostAddress();
    }

    public void stop( Serializable sessionId ) throws InvalidSessionException {
        Session s = retrieveAndValidateSession( sessionId );
        stop( s );
    }

    public Object getAttribute( Serializable sessionId, Object key )
        throws InvalidSessionException {
        return retrieveAndValidateSession( sessionId ).getAttribute( key );
    }

    public void setAttribute( Serializable sessionId, Object key, Object value )
        throws InvalidSessionException {
        retrieveAndValidateSession( sessionId ).setAttribute( key, value );
    }

    public Object removeAttribute( Serializable sessionId, Object key )
        throws InvalidSessionException {
        return retrieveAndValidateSession( sessionId ).removeAttribute( key );
    }
}
