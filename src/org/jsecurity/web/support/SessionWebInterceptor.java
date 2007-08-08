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
package org.jsecurity.web.support;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SessionWebInterceptor extends SecurityWebInterceptor implements Initializable {

    /**
     * Key that may be used for a http request or session attribute to alert that a referencing JSecurity Session
     * has expired.
     */
    public static final String EXPIRED_SESSION_KEY = SessionWebInterceptor.class.getName() + "_EXPIRED_SESSION_KEY";

    private WebSessionFactory webSessionFactory = null;
    private SessionFactory sessionFactory = null;

    public void setWebSessionFactory( WebSessionFactory webSessionFactory ) {
        this.webSessionFactory = webSessionFactory;
    }

    public WebSessionFactory getWebSessionFactory() {
        return webSessionFactory;
    }

    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void init() {
        if ( getWebSessionFactory() == null ) {
            WebSessionFactory wsf = createWebSessionFactory();
            if ( wsf == null ) {
                String msg = "createWebSessionFactory implementation must return a non-null WebSessionFactory instance.";
                throw new IllegalStateException( msg );
            }
            setWebSessionFactory( wsf );
        }
    }

    protected WebSessionFactory createWebSessionFactory() {
        SessionFactory sessionFactory = getSessionFactory();
        if ( sessionFactory == null ) {
            String msg = "The SessionFactory property must be set if the WebSessionFactory property is not set.";
            throw new IllegalStateException( msg );
        }
        return new DefaultWebSessionFactory( sessionFactory );
    }

    protected void bindToThread( Session session ) {
        ThreadContext.bind( session );
    }

    protected void unbindSessionFromThread() {
        ThreadContext.unbindSession();
    }

    protected Session acquireSession( HttpServletRequest request, HttpServletResponse response ) {

        Session session;

        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if ( webSessionFactory == null ) {
            String msg = "webSessionFactory property must be set.  This will be automatically created during " +
                "init() if the sessionFactory property is set, or of course, you can inject a " +
                "WebSessionFactory instance directly.";
            throw new IllegalStateException( msg );
        }

        try {
            session = webSessionFactory.getSession( request, response );
            if ( session == null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No JSecurity Session associated with the HttpServletRequest.  " +
                               "Attempting to create a new one." );
                }
                session = webSessionFactory.start( request, response );
                if ( log.isDebugEnabled() ) {
                    log.debug( "Created new JSecurity Session with id [" + session.getSessionId() + "]" );
                }
            } else {
                //update last accessed time:
                session.touch();
            }
        } catch ( InvalidSessionException ise ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Request JSecurity Session is invalid, message: [" + ise.getMessage() + "]." );
            }
            session = handleInvalidSession( request, response, ise );
        }

        return session;
    }

    protected Session handleInvalidSession( HttpServletRequest request,
                                            HttpServletResponse response,
                                            InvalidSessionException ise ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Handling invalid session associated with the request.  Attempting to " +
                       "create a new Session to allow processing to continue" );
        }
        Session session = getWebSessionFactory().start( request, response );

        if ( log.isTraceEnabled() ) {
            log.trace( "Adding EXPIRED_SESSION_KEY as a request attribute to alert that the request's incoming " +
                       "referenced session had expired." );
        }
        request.setAttribute( EXPIRED_SESSION_KEY, Boolean.TRUE );

        return session;
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        Session session  = acquireSession( request, response );
        if ( session != null ) {
            bindToThread( session );
        }
        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );
        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        //no need to do anything here.  The WebSessionFactory binds the session id to
        //the response to ensure it is available on subsequent requests to re-construct a Session object.
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception )
        throws Exception {
        unbindSessionFromThread();
        unbindInetAddressFromThread();
    }
}
