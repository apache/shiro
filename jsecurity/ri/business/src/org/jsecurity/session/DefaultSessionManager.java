/*
 * Copyright (C) 2005 Les A. Hazlewood
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
package org.jsecurity.session;

import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.eis.SessionDAO;
import org.jsecurity.session.event.SessionEventSender;
import org.jsecurity.session.event.SessionEvent;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Calendar;
import java.security.Principal;

/**
 * @author Les Hazlewood
 * @version $Revision$ $Date$
 */
public class DefaultSessionManager implements SessionManager {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SessionDAO sessionDAO = null;
    protected SessionEventSender sessionEventSender = null;

    public DefaultSessionManager(){}

    public void setSessionDAO( SessionDAO sessionDAO ) {
        this.sessionDAO = sessionDAO;
    }

    public void setSessionEventSender( SessionEventSender sessionEventSender ) {
        this.sessionEventSender = sessionEventSender;
    }

    public void init() {
        if ( sessionDAO == null ) {
            String msg = "sessionDAO property has not been set.  The sessionDAO is required to " +
                         "access session objects during runtime.";
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
            if ( log.isDebugEnabled() ) {
                String msg = "No sessionEventSender set.  Event of type [" +
                    event.getClass().getName() + "] will not be propagated.";
                log.debug( msg );
            }
        }
    }


    public Serializable start( InetAddress originatingHost )
        throws HostUnauthorizedException, IllegalArgumentException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Calendar getStartTimestamp( Serializable sessionId ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Calendar getStopTimestamp( Serializable sessionId ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Calendar getLastAccessTime( Serializable sessionId ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean isAuthenticated( Serializable sessionId ) {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean isStopped( Serializable sessionId ) {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public boolean isExpired( Serializable sessionId ) {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void touch( Serializable sessionId ) throws ExpiredSessionException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Principal getPrincipal( Serializable sessionId ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public InetAddress getHostAddress( Serializable sessionId ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void stop( Serializable sessionId ) throws ExpiredSessionException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Object getAttribute( Serializable sessionId, Object key )
        throws ExpiredSessionException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void setAttribute( Serializable sessionId, Object key, Object value )
        throws ExpiredSessionException, IllegalArgumentException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public Object removeAttribute( Serializable sessionId, Object key )
        throws ExpiredSessionException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
