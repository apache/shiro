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
import org.jsecurity.session.event.support.SimpleSessionEventSender;
import org.jsecurity.session.support.eis.SessionDAO;
import org.jsecurity.util.Initializable;

import java.io.Serializable;
import java.net.InetAddress;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Date;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractSessionManager implements SessionManager, SessionEventNotifier, Initializable {

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SessionDAO sessionDAO = null;
    protected SimpleSessionEventSender sessionEventSender = null; //will only be created if session event listeners are registered.
    protected boolean validateHost = false;
    protected Class<? extends Session> sessionClass = null;

    protected boolean touchSessionOnRead = false;

    public AbstractSessionManager(){}

    public void setSessionDAO( SessionDAO sessionDAO ) {
        this.sessionDAO = sessionDAO;
    }

    public SessionDAO getSessionDAO() {
        return this.sessionDAO;
    }

    protected SimpleSessionEventSender ensureSessionEventSender() {
        if ( this.sessionEventSender == null ) {
            this.sessionEventSender = new SimpleSessionEventSender();
        }
        return this.sessionEventSender;
    }

    public void add( SessionEventListener listener ) {
        ensureSessionEventSender().add( listener );
    }

    public boolean remove( SessionEventListener listener ) {
        return ensureSessionEventSender().remove( listener );
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
     * <p>The default value is <tt>false</tt>, to account for localhost and proxy environments.
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
     * Returns whether or not a read only operation on a persisted session (e.g.
     * {@link org.jsecurity.session.Session#getHostAddress() getHostAddress},
     * {@link Session#getAttribute(Object) getAttribute(Object)}, etc. would '{@link Session#touch() touch}' the session
     * object (i.e. usually updating the last access time stamp at a minimum).  Note that a write operation
     * ({@link Session#setAttribute(Object, Object)}, etc) will <em>always</tt> touch a session, regardless of this
     * setting.
     *
     * <p>The default is <tt>false</tt> such that read-only operations do _not_ 'touch' the Session.
     *
     * <p>It is important to understand what this means for your application, especially as it pertains to
     * session time/orphan validation: typically orphaned sessions are reaped based on a
     * <tt>Session</tt>'s {@link org.jsecurity.session.Session#getLastAccessTime() lastAccessTime}stamp, so if a session
     * is only 'touched' on a write operation (default), then a session must be altered on a regular basis in order for
     * it to not be reaped.  This is ok in 95% of applications, since Session objects are regularly modified.
     *
     * <p>In applications that don't modify the attributes internally very often, the application is of course always
     * free to explicitcly call the {@link Session#touch() touch} method to avoid session timeout.
     *  
     * @return whether or not a read only operation on a persisted session would 'touch' it, thereby likely changing
     * its internal state and causing an eis update.  Default is <tt>false</tt>.
     */
    public boolean isTouchSessionOnRead() {
        return touchSessionOnRead;
    }

    public void setTouchSessionOnRead( boolean touchSessionOnRead ) {
        this.touchSessionOnRead = touchSessionOnRead;
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

    protected SessionEvent createStartEvent( Session session ) {
        return new StartedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createStopEvent( Session session ) {
        return new StoppedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createExpireEvent( Session session ) {
        return new ExpiredSessionEvent( this, session.getSessionId() );
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
     *
     * <p>The default implementation just ensures the value is not null and throws an
     * {@link IllegalArgumentException} if this is the case.
     *
     * <p>Subclasses may override this
     * method to do any number of checks, such as ensuring the originatingHost is in a valid
     * range, part of a particular subnet, or configured in the database as a valid IP.
     * 
     * @param originatingHost the originating host address associated with the session
     * creation attempt.
     * @throws IllegalArgumentException if the originatingHost argument is <tt>null</tt>
     */
    protected void validate( InetAddress originatingHost ) {
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
        session.stop();
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
        session.stop();
        onExpire( session );
        sessionDAO.update( session );
        send( createExpireEvent( session ) );
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
            long timeout = getTimeout( session );

            Serializable sessionId = session.getSessionId();

            DateFormat df = DateFormat.getInstance();
            String msg = "Session with id [" + sessionId + "] has expired. " +
                         "Last access time: " + df.format( lastAccessTime ) +
                         ".  Current time: " + df.format( new Date() ) +
                         ".  Session timeout is set to " + timeout/MILLIS_PER_SECOND + " seconds (" +
                         timeout / MILLIS_PER_MINUTE + " minutes)";
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
     * @return true if expiration is enabled for the specified session, false otherwise.
     */
    protected boolean isExpirationEnabled( Session session ) {
        return true;
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
    protected long getTimeout( Session session ) {
        return session.getTimeout();
    }

    /**
     * Determines if the specified session is expired.
     * @param session the persistent pojo Session implementation to check for expiration.
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

            long timeout = getTimeout( session );

            if ( timeout >= 0l ) {

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
                // before this time, it is expired.
                long expireTimeMillis = System.currentTimeMillis() - timeout;
                Date expireTime = new Date( expireTimeMillis );
                return lastAccessTime.before( expireTime );
            } else {
                if ( log.isTraceEnabled() ) {
                    log.trace( "No timeout for session with id [" + session.getSessionId() +
                              "].  Session is not considered expired." );
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Time-out is disabled for Session with id [" + session.getSessionId() +
                          "].  Session is not expired." );
            }
        }

        return false;
    }

    protected Session retrieveSessionForUpdate( Serializable sessionId ) throws InvalidSessionException {
        Session s = retrieveAndValidateSession( sessionId );
        s.touch();
        onTouch( s );
        return s;
    }

    protected void onTouch( Session session ){}

    protected Session getSession( Serializable sessionId ) throws InvalidSessionException {
        if ( isTouchSessionOnRead() ) {
            return retrieveSessionForUpdate( sessionId );
        } else {
            return retrieveAndValidateSession( sessionId );
        }
    }


    /* ================================================
       Interface implementation / proxy support methods
       ================================================ */
    public Serializable start( InetAddress originatingHost )
        throws HostUnauthorizedException, IllegalArgumentException {
        Session s = createSession( originatingHost );
        send( createStartEvent( s ) );
        return s.getSessionId();
    }

    public Date getStartTimestamp( Serializable sessionId ) {
        return getSession( sessionId ).getStartTimestamp();
    }

    public Date getStopTimestamp( Serializable sessionId ) {
        return retrieveSession( sessionId ).getStopTimestamp();
    }

    public Date getLastAccessTime( Serializable sessionId ) {
        return getSession( sessionId ).getLastAccessTime();
    }

    public boolean isStopped( Serializable sessionId ) {
        return getStopTimestamp( sessionId ) != null;
    }

    public boolean isExpired( Serializable sessionId ) {
        try {
            getSession( sessionId );
            //no exception thrown, return false;
            return false;
        } catch ( SessionException e ) {
            return true;
        }
    }

    public long getTimeout( Serializable sessionId ) throws InvalidSessionException {
        return getTimeout( getSession( sessionId ) );
    }

    public void setTimeout( Serializable sessionId, long maxIdleTimeInMillis ) throws InvalidSessionException {
        Session s = retrieveSessionForUpdate( sessionId );
        s.setTimeout( maxIdleTimeInMillis );
        onSetTimeout( s );
        sessionDAO.update( s );
    }

    protected void onSetTimeout( Session session ) {}

    public void touch( Serializable sessionId ) throws InvalidSessionException {
        Session s = retrieveSessionForUpdate( sessionId );
        sessionDAO.update( s );
    }

    public InetAddress getHostAddress( Serializable sessionId ) {
        return getSession( sessionId ).getHostAddress();
    }

    public void stop( Serializable sessionId ) throws InvalidSessionException {
        Session s = retrieveSessionForUpdate( sessionId );
        stop( s );
    }

    public Collection<Object> getAttributeKeys( Serializable sessionId ) {
        return getSession( sessionId ).getAttributeKeys();
    }

    public Object getAttribute( Serializable sessionId, Object key )
        throws InvalidSessionException {
        return getSession( sessionId ).getAttribute( key );
    }

    public void setAttribute( Serializable sessionId, Object key, Object value )
        throws InvalidSessionException {
        Session s = retrieveSessionForUpdate( sessionId );
        s.setAttribute( key, value );
        sessionDAO.update( s );
    }

    public Object removeAttribute( Serializable sessionId, Object key )
        throws InvalidSessionException {
        Session s = retrieveSessionForUpdate( sessionId );
        Object removed = s.removeAttribute( key );
        sessionDAO.update( s );
        return removed;
    }
}
