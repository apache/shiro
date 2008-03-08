package org.jsecurity.web.session;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.web.servlet.JSecurityHttpSession;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class WebSession implements Session {

    private static final String TOUCH_OBJECT_SESSION_KEY = WebSession.class.getName() + "_TOUCH_OBJECT_SESSION_KEY";

    private HttpSession httpSession = null;
    private InetAddress inetAddress = null;

    public WebSession( HttpSession httpSession, InetAddress inetAddress ) {
        if ( httpSession == null ) {
            String msg = "HttpSession constructor argument cannot be null.";
            throw new IllegalArgumentException( msg );
        }
        if ( httpSession instanceof JSecurityHttpSession ) {
            String msg = "HttpSession constructor argument cannot be an instance of JSecurityHttpSession.  This " +
                "is enforced to prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException( msg );
        }
        this.httpSession = httpSession;
        this.inetAddress = inetAddress;
    }

    public Serializable getId() {
        return httpSession.getId();
    }

    public Date getStartTimestamp() {
        return new Date( httpSession.getCreationTime() );
    }

    public Date getStopTimestamp() {
        return null;
    }

    public Date getLastAccessTime() {
        return new Date( httpSession.getLastAccessedTime() );
    }

    public boolean isExpired() {
        return false;
    }

    public long getTimeout() throws InvalidSessionException {
        try {
            return httpSession.getMaxInactiveInterval() * 1000;
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    public void setTimeout( long maxIdleTimeInMillis ) throws InvalidSessionException {
        try {
            int timeout = Long.valueOf( maxIdleTimeInMillis / 1000 ).intValue();
            httpSession.setMaxInactiveInterval( timeout );
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    public InetAddress getHostAddress() {
        return this.inetAddress;
    }

    public void touch() throws InvalidSessionException {
        //just manipulate the session to update the access time:
        try {
            httpSession.setAttribute( TOUCH_OBJECT_SESSION_KEY, TOUCH_OBJECT_SESSION_KEY );
            httpSession.removeAttribute( TOUCH_OBJECT_SESSION_KEY );
        } catch ( Exception e ) {
            throw new InvalidSessionException( e ); 
        }
    }

    public void stop() throws InvalidSessionException {
        try {
            httpSession.invalidate();
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        try {
            Enumeration namesEnum = httpSession.getAttributeNames();
            Collection<Object> keys = null;
            if (namesEnum != null ) {
                keys = new ArrayList<Object>();
                while( namesEnum.hasMoreElements() ) {
                    keys.add( namesEnum.nextElement() );
                }
            }
            return keys;
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    private static String assertString( Object key ) {
        if ( !(key instanceof String) ) {
            String msg = "HttpSession based implementations of the JSecurity Session interface requires attribute keys " +
                "to be String objects.  The HttpSession class does not support anything other than String keys.";
            throw new IllegalArgumentException( msg );
        }
        return (String)key;
    }

    public Object getAttribute( Object key ) throws InvalidSessionException {
        try {
            return httpSession.getAttribute( assertString(key) );
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    public void setAttribute( Object key, Object value ) throws InvalidSessionException {
        try {
            httpSession.setAttribute( assertString(key), value );
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }

    public Object removeAttribute( Object key ) throws InvalidSessionException {
        try {
            String sKey = assertString( key );
            Object removed = httpSession.getAttribute( sKey );
            httpSession.removeAttribute( sKey );
            return removed;
        } catch ( Exception e ) {
            throw new InvalidSessionException( e );
        }
    }
}
