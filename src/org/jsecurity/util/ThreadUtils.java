/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.util;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;

import java.net.InetAddress;

/**
 * Utility method class used to bind and unbind {@link Session Session}s and
 * {@link org.jsecurity.context.SecurityContext SecurityContext}s to the thread.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class ThreadUtils {

    private ThreadUtils(){}

    public static void bindToThread( SecurityContext secCtx ) {
        if ( secCtx != null ) {
            ThreadContext.put( ThreadContext.SECURITY_CONTEXT_KEY, secCtx );
        }
    }

    public static void unbindSecurityContextFromThread() {
        ThreadContext.remove( ThreadContext.SECURITY_CONTEXT_KEY );
    }

    public static void bindToThread( Session s ) {
        if ( s != null ) {
            ThreadContext.put( ThreadContext.SESSION_KEY, s );
        }
    }

    public static void unbindSessionFromThread() {
        ThreadContext.remove( ThreadContext.SESSION_KEY );
    }

    public static void bindToThread( InetAddress ip ) {
        if ( ip != null ) {
            ThreadContext.put( ThreadContext.INET_ADDRESS_KEY, ip );
        }
    }

    public static void unbindInetAddressFromThread() {
        ThreadContext.remove( ThreadContext.INET_ADDRESS_KEY );
    }

}
