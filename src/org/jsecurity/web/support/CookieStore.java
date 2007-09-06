package org.jsecurity.web.support;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.beans.PropertyEditor;

/**
 * A <tt>CookieStore</tt> stores an object as a {@link Cookie} for access on later requests.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class CookieStore<T> extends AbstractWebStore<T> {

    protected static final int ONE_YEAR = 60 * 60 * 24 * 365;
    protected static final int INDEFINITE = Integer.MAX_VALUE;

    private String path = null; //null means set it on the request context root
    private int maxAge = -1; //expire on browser close
    private boolean secure = false;

    public CookieStore() {
    }

    /**
     * Constructs a <tt>CookieStore</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getPath() path}.
     *
     * <p>A <tt>null</tt> <tt>path</tt> value means the request context's path will be used by default.
     *
     * <p>The Cookie's {@link Cookie#getMaxAge() maxAge} will be <tt>-1</tt>, indicating the Cookie will persist until
     * browser shutdown.
     *
     * @param name the Cookie {@link Cookie#getName() name}
     * @param path the Cookie {@link Cookie#setPath(String) path}.
     */
    public CookieStore( String name, String path ) {
        super( name );
        setPath( path );
    }

    /**
     * Constructs a <tt>CookieStore</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name} and {@link Cookie#getMaxAge() maxAge}.
     *
     * <p>The Cookie's {@link javax.servlet.http.Cookie#getPath() path} will be the <tt>Request</tt>'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path}.
     *
     * @param name   the Cookie {@link javax.servlet.http.Cookie#getName() name};
     * @param maxAge the Cookie {@link Cookie#getMaxAge() maxAge}
     */
    public CookieStore( String name, int maxAge ) {
        super( name );
        setMaxAge( maxAge );
    }

    /**
     * Constructs a <tt>CookieStore</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name}, {@link javax.servlet.http.Cookie#getPath() path}, and
     * {@link Cookie#getMaxAge() maxAge}.
     *
     * @param name   the Cookie {@link Cookie#getName() name}
     * @param path   the Cookie {@link Cookie#setPath(String) path}.
     * @param maxAge the Cookie {@link Cookie#getMaxAge() maxAge}
     */
    public CookieStore( String name, String path, int maxAge ) {
        this( name, path );
        setMaxAge( maxAge );
    }

    /**
     * Constructs a <tt>CookieStore</tt> using a {@link Cookie Cookie} with the specified
     * {@link Cookie#getName() name}, {@link javax.servlet.http.Cookie#getPath() path}, and
     * {@link Cookie#getMaxAge() maxAge}, utilizing the specified <tt>PropertyEditor</tt> to perform value/string
     * conversion on the object stored as a cookie.
     *
     * @param name        the Cookie {@link Cookie#getName() name}
     * @param path        the Cookie {@link Cookie#setPath(String) path}.
     * @param maxAge      the Cookie {@link Cookie#getMaxAge() maxAge}
     * @param editorClass the <tt>PropertyEditor</tt> to perform value/string conversion on the object stored as a
     *                    Cookie.
     */
    public CookieStore( String name, String path, int maxAge, Class<? extends PropertyEditor> editorClass ) {
        super( name, editorClass );
        setPath( path );
        setMaxAge( maxAge );
    }

    /**
     * Returns the Cookie's {@link Cookie#getPath() path} setting.  If <tt>null</tt>, the <tt>request</tt>'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     * @return the Cookie's path, or <tt>null</tt> if the request's context path should be used as the path when the
     * cookie is created.
     */
    public String getPath() {
        return path;
    }

    /**
     * Sets the Cookie's {@link Cookie#getPath() path} setting.  If the argument is <tt>null</tt>, the <tt>request</tt>'s
     * {@link javax.servlet.http.HttpServletRequest#getContextPath() context path} will be used.
     * @param path the Cookie's path, or <tt>null</tt> if the request's context path should be used as the path when the
     * cookie is created.
     */
    public void setPath( String path ) {
        this.path = path;
    }

    /**
     * Returns the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     * @return the Cookie's {@link Cookie#setMaxAge(int) maxAge}
     */
    public int getMaxAge() {
        return maxAge;
    }

    /**
     * Sets the Cookie's {@link Cookie#setMaxAge(int) maxAge} setting.  Please see that JavaDoc for the semantics on
     * the repercussions of negative, zero, and positive values for the maxAge.
     * @param maxAge the Cookie's {@link Cookie#setMaxAge(int) maxAge}
     */
    public void setMaxAge( int maxAge ) {
        this.maxAge = maxAge;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure( boolean secure ) {
        this.secure = secure;
    }

    /**
     * Returns the cookie with the given name from the request or <tt>null</tt> if no cookie
     * with that name could be found.
     *
     * @param request    the current executing http request.
     * @param cookieName the name of the cookie to find and return.
     * @return the cookie with the given name from the request or <tt>null</tt> if no cookie
     *         with that name could be found.
     */
    private static Cookie getCookie( HttpServletRequest request, String cookieName ) {
        Cookie cookies[] = request.getCookies();
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                if ( cookie.getName().equals( cookieName ) ) {
                    return cookie;
                }
            }
        }
        return null;
    }

    public T onRetrieveValue( HttpServletRequest request, HttpServletResponse response ) {
        T value = null;

        String stringValue = null;
        Cookie cookie = getCookie( request, getName() );
        if ( cookie != null ) {
            stringValue = cookie.getValue();
            if ( log.isInfoEnabled() ) {
                log.info( "Found string value [" + stringValue + "] from HttpServletRequest Cookie [" + getName() + "]" );
            }
            value = fromStringValue( stringValue );
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No value found in request Cookies under cookie name [" + getName() + "]" );
            }
        }

        return value;
    }

    public void onStoreValue( T value, HttpServletRequest request, HttpServletResponse response ) {

        String name = getName();
        String path = getPath();
        int maxAge = getMaxAge();

        if ( path == null ) {
            path = request.getContextPath();
        }

        String stringValue = toStringValue( value );
        Cookie idCookie = new Cookie( name, stringValue );
        idCookie.setMaxAge( maxAge );
        idCookie.setPath( path );
        if ( isSecure() ) {
            idCookie.setSecure( true );
        }

        response.addCookie( idCookie );
        if ( log.isTraceEnabled() ) {
            log.trace( "Added Cookie [" + name + "] to path [" + path + "] with value [" +
                stringValue + "] to the HttpServletResponse." );
        }
    }

}
