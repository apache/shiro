package org.jsecurity.web.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Uses the <tt>HttpSession</tt> as the underlying storage mechanism, using the {@link #getName() name} attribute as
 * the session key.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class HttpSessionStore<T> extends AbstractWebStore<T> {

    public HttpSessionStore() {
        super();
    }

    public HttpSessionStore( String name ) {
        super( name );
    }

    public HttpSessionStore( String name, boolean checkRequestParams ) {
        super( name, checkRequestParams );
    }

    public T onRetrieveValue( HttpServletRequest request, HttpServletResponse response ) {
        T value = null;

        HttpSession session = request.getSession( false );
        if ( session != null ) {
            value = (T)session.getAttribute( getName() );
        }

        if ( value != null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Found value [" + value + "] via HttpSession key [" + getName() + "]" );
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No value fround in HttpSession via session key [" + getName() + "]" );
            }
        }

        return value;
    }

    public void onStoreValue( T value, HttpServletRequest request, HttpServletResponse response ) {
        HttpSession session = request.getSession();
        if ( session != null && value != null) {
            session.setAttribute( getName(), value );
            if ( log.isDebugEnabled() ) {
                log.debug( "Set HttpSession attribute [" + getName() + "] with value [" + value + "]" );
            }
        }
    }
}
