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
package org.jsecurity.web.servlet;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.web.session.WebSession;

import javax.servlet.ServletContext;
import javax.servlet.http.*;
import java.util.*;

/**
 * Wrapper class that uses a JSecurity session under the hood for all session operations instead of the
 * Servlet Container's session mechanism.  This is preferred in heterogeneous client environments where the Session
 * is used on both the business tier as well as in multiple client technologies (web, swing, flash, etc).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
@SuppressWarnings("deprecated")
public class JSecurityHttpSession implements HttpSession {

    public static final String DEFAULT_SESSION_ID_NAME = "JSESSIONID";

    private static final Enumeration EMPTY_ENUMERATION = new Enumeration() {
        public boolean hasMoreElements() {
            return false;
        }

        public Object nextElement() {
            return null;
        }
    };

    private static final HttpSessionContext HTTP_SESSION_CONTEXT = new HttpSessionContext() {
        public HttpSession getSession( String s ) {
            return null;
        }

        public Enumeration getIds() {
            return EMPTY_ENUMERATION;
        }
    };

    protected ServletContext servletContext = null;
    protected HttpServletRequest currentRequest = null;
    protected Session session = null; //'real' JSecurity Session

    public JSecurityHttpSession( Session session, HttpServletRequest currentRequest, ServletContext servletContext ) {
        if ( session instanceof WebSession) {
            String msg = "Session constructor argument cannot be an instance of WebSession.  This is enforced to " +
                "prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException( msg );
        }
        this.session = session;
        this.currentRequest = currentRequest;
        this.servletContext = servletContext;
    }

    public Session getSession() {
        return this.session;
    }

    public long getCreationTime() {
        try {
            return getSession().getStartTimestamp().getTime();
        } catch ( Exception e ) {
            throw new IllegalStateException( e );
        }
    }

    public String getId() {
        return getSession().getSessionId().toString();
    }

    public long getLastAccessedTime() {
        return getSession().getLastAccessTime().getTime();
    }

    public ServletContext getServletContext() {
        return this.servletContext;
    }

    public void setMaxInactiveInterval( int i ) {
        try {
            getSession().setTimeout( i * 1000 );
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
    }

    public int getMaxInactiveInterval() {
        try {
            return ( new Long( getSession().getTimeout() / 1000 ) ).intValue();
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
    }

    public HttpSessionContext getSessionContext() {
        return HTTP_SESSION_CONTEXT;
    }

    public Object getAttribute( String s ) {
        try {
            return getSession().getAttribute( s );
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
    }

    public Object getValue( String s ) {
        return getAttribute( s );
    }

    protected Set<String> getKeyNames() {
        Collection<Object> keySet = null;
        try {
            keySet = getSession().getAttributeKeys();
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
        Set<String> keyNames = null;
        if ( keySet != null && !keySet.isEmpty() ) {
            keyNames = new HashSet<String>( keySet.size() );
            for ( Object o : keySet ) {
                keyNames.add( o.toString() );
            }
        } else {
            keyNames = Collections.EMPTY_SET;
        }
        return keyNames;
    }

    public Enumeration getAttributeNames() {
        Set<String> keyNames = getKeyNames();
        final Iterator iterator = keyNames.iterator();
        return new Enumeration() {
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            public Object nextElement() {
                return iterator.next();
            }
        };
    }

    public String[] getValueNames() {
        Set<String> keyNames = getKeyNames();
        String[] array = new String[keyNames.size()];
        if ( keyNames.size() > 0 ) {
            array = keyNames.toArray( array );
        }
        return array;
    }

    protected void beforeBound( String s, Object o ) {
        if ( o instanceof HttpSessionBindingListener ) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener)o;
            HttpSessionBindingEvent event = new HttpSessionBindingEvent( this, s, o );
            listener.valueBound( event );
        }
    }

    protected void afterUnbound( String s, Object o ) {
        if ( o instanceof HttpSessionBindingListener ) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener)o;
            HttpSessionBindingEvent event = new HttpSessionBindingEvent( this, s, o );
            listener.valueUnbound( event );
        }
    }

    public void setAttribute( String s, Object o ) {
        beforeBound( s, o );
        try {
            getSession().setAttribute( s, o );
        } catch ( InvalidSessionException e ) {
            afterUnbound( s, o );
            throw new IllegalStateException( e );
        }
    }

    public void putValue( String s, Object o ) {
        setAttribute( s, o );
    }

    public void removeAttribute( String s ) {
        try {
            Object attribute = getSession().removeAttribute( s );
            afterUnbound( s, attribute );
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
    }

    public void removeValue( String s ) {
        removeAttribute( s );
    }

    public void invalidate() {
        try {
            getSession().stop();
        } catch ( InvalidSessionException e ) {
            throw new IllegalStateException( e );
        }
    }

    public boolean isNew() {
        Boolean value = (Boolean)currentRequest.getAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_IS_NEW );
        return value != null && value.equals( Boolean.TRUE );
    }
}
