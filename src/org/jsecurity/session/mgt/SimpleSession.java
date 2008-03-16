/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
