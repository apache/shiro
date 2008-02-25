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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.ThreadContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Convenient superclass for web objects that need access to security components, such as the Subject,
 * Session, or IP address.  There is no requirement for classes to extend from this class, although many
 * web framework classes derive from this base class.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class SecurityWebSupport implements Initializable {

    private static transient final Log staticLog = LogFactory.getLog( SecurityWebSupport.class );
    protected transient final Log log = LogFactory.getLog( getClass() );

    public static InetAddress getInetAddress( ServletRequest request ) {
        InetAddress clientAddress = null;
        //get the Host/IP the client is coming from:
        String addrString = request.getRemoteHost();
        try {
            clientAddress = InetAddress.getByName( addrString );
        } catch ( UnknownHostException e ) {
            if ( staticLog.isInfoEnabled() ) {
                staticLog.info( "Unable to acquire InetAddress from HttpServletRequest", e );
            }
        }

        return clientAddress;
    }

    public Subject getSubject( ServletRequest request, ServletResponse response ) {
        return ThreadContext.getSubject();
    }

    protected Session getSession( ServletRequest request, ServletResponse response ) {

        Session session = null;

        Subject subject = getSubject( request, response );

        if ( subject != null ) {
            session = subject.getSession( false );
        }

        return session;
    }

    protected HttpServletRequest toHttp( ServletRequest request ) {
        return (HttpServletRequest)request;
    }

    protected HttpServletResponse toHttp( ServletResponse response ) {
        return (HttpServletResponse)response;
    }

    protected static void bindInetAddressToThread( ServletRequest request ) {
        InetAddress ip = getInetAddress( request );
        if ( ip != null ) {
            ThreadContext.bind( ip );
        }
    }

    protected static void unbindInetAddressFromThread() {
        ThreadContext.unbindInetAddress();
    }

}
