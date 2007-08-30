package org.jsecurity.web.support;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Uses the JSecurity <tt>Session</tt> object as the underlying storage mechanism, using the {@link #getName() name}
 * attribute as the session key.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SessionStore<T> extends AbstractWebStore<T> {

    public SessionStore() {
        super();
    }

    public SessionStore( String name ) {
        super( name );
    }

    public SessionStore( String name, boolean checkRequestParams ) {
        super( name, checkRequestParams );
    }

    protected Session getSession( HttpServletRequest request, HttpServletResponse response ) {

        Session session = null;

        SecurityContext securityContext = getSecurityContext( request, response );

        if ( securityContext != null ) {
            session = securityContext.getSession( false );
        }

        return session;
    }

    public T onRetrieveValue( HttpServletRequest request, HttpServletResponse response ) {
        T value = null;

        Session session = getSession( request, response );
        if ( session != null ) {
            value = (T)session.getAttribute( getName() );
        }

        if ( value != null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Found value [" + value + "] via JSecurity Session key [" + getName() + "]" );
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No value fround in JSecurity Session via session key [" + getName() + "]" );
            }
        }

        return value;
    }

    public void onStoreValue( T value, HttpServletRequest request, HttpServletResponse response ) {
        SecurityContext securityContext = getSecurityContext( request, response );
        if ( securityContext != null ) {
            Session session = securityContext.getSession();
            if ( session != null ) {
                session.setAttribute( getName(), value );
                if ( log.isDebugEnabled() ) {
                    log.debug( "Set JSecurity Session attribute [" + getName() + "] with value [" + value + "]" );
                }
            }
        }
    }
}
