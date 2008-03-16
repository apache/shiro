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
package org.jsecurity.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityUtils;
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
        return SecurityUtils.getSubject();
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
