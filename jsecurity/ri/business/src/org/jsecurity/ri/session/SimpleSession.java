/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.ri.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple {@link org.jsecurity.session.Session} implementation, intended to be used on the business/server tier.
 * 
 * @since 0.1
 * @author Les Hazlewood
 */
public class SimpleSession implements Session, Serializable {

    private final transient Log log = LogFactory.getLog( getClass() );

    private Serializable sessionId = null;
    private Date startTimestamp = null;
    private Date stopTimestamp = null;
    private Date lastAccessTime = null;
    private boolean expired = false;
    private InetAddress hostAddress = null;

    private Map<Object, Object> attributes = null;

    public SimpleSession() {

        //JSecurity uses UUID's by default.  This can be overridden via the setSessionId method:
        sessionId = java.util.UUID.randomUUID();
        startTimestamp = new Date();
        lastAccessTime = startTimestamp; //default when first instantiated
        try {
            hostAddress = InetAddress.getLocalHost();
        } catch ( Exception e ) {
            if ( log.isWarnEnabled() ) {
                log.warn( "Unable to acquire localhost address from " +
                          "method call java.net.InetAddress.getLocalHost().  hostAddress " +
                          "will be null", e );
            }
        }

        attributes = new HashMap<Object,Object>();
    }

    public Serializable getSessionId() {
        return this.sessionId;
    }

    public void setSessionId( Serializable sessionId ) {
        this.sessionId = sessionId;
    }

    public Date getStartTimestamp() {
        return startTimestamp;
    }

    public void setStartTimestamp( Date startTimestamp ) {
        this.startTimestamp = startTimestamp;
    }

    public Date getStopTimestamp() {
        return stopTimestamp;
    }

    public void setStopTimestamp( Date stopTimestamp ) {
        this.stopTimestamp = stopTimestamp;
    }

    public Date getLastAccessTime() {
        return lastAccessTime;
    }

    public void setLastAccessTime( Date lastAccessTime ) {
        this.lastAccessTime = lastAccessTime;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired( boolean expired ) {
        this.expired = expired;
    }

    public InetAddress getHostAddress() {
        return hostAddress;
    }

    public void setHostAddress( InetAddress hostAddress ) {
        this.hostAddress = hostAddress;
    }

    public Map<Object, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes( Map<Object, Object> attributes ) {
        this.attributes = attributes;
    }

    public void touch() {
        this.lastAccessTime = new Date();
    }

    public void stop() {
        this.stopTimestamp = new Date();
    }

    public Object getAttribute( Object key ) {
        return getAttributes().get( key );
    }

    public void setAttribute( Object key, Object value ) {
        if ( value == null ) {
            removeAttribute( key );
        } else {
            getAttributes().put( key, value );
        }
    }

    public Object removeAttribute( Object key ) {
        return getAttributes().remove( key );
    }

}
