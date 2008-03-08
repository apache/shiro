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
package org.jsecurity.session.mgt;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Simple {@link org.jsecurity.session.Session} implementation, intended to be used on the business/server tier.
 * 
 * @since 0.1
 * @author Les Hazlewood
 */
public class SimpleSession implements Session, Serializable {

    private Serializable id = null;
    private Date startTimestamp = null;
    private Date stopTimestamp = null;
    private Date lastAccessTime = null;
    private long timeout = DefaultSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT;
    private boolean expired = false;
    private InetAddress hostAddress = null;

    private Map<Object, Object> attributes = null;

    public SimpleSession() {
        this(getLocalHost());
    }

    public SimpleSession( InetAddress hostAddress ) {
        this.startTimestamp = new Date();
        this.lastAccessTime = startTimestamp;
        this.hostAddress = hostAddress;
    }

    private static InetAddress getLocalHost() {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    public Serializable getId() {
        return this.id;
    }

    public void setId( Serializable id) {
        this.id = id;
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

    public long getTimeout() {
        return timeout;
    }

    public void setTimeout( long timeout ) {
        this.timeout = timeout;
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

    private Map<Object,Object> getAttributesLazy() {
        Map<Object,Object> attributes = getAttributes();
        if ( attributes == null ) {
            attributes = new HashMap<Object,Object>();
            setAttributes( attributes );
        }
        return attributes;
    }

    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        Map<Object,Object> attributes = getAttributes();
        if ( attributes == null ) {
            //noinspection unchecked
            return Collections.EMPTY_SET;
        }
        return attributes.keySet();
    }

    public Object getAttribute( Object key ) {
        Map<Object,Object> attributes = getAttributes();
        if ( attributes == null ) {
            return null;
        }
        return attributes.get( key );
    }

    public void setAttribute( Object key, Object value ) {
        if ( value == null ) {
            removeAttribute( key );
        } else {
            getAttributesLazy().put( key, value );
        }
    }

    public Object removeAttribute( Object key ) {
        Map<Object,Object> attributes = getAttributes();
        if ( attributes == null ) {
            return null;
        } else {
            return attributes.remove( key );
        }
    }

}
