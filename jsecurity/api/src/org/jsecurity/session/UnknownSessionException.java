/*
 * Copyright (C) 2005 Les A. Hazlewood
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
package org.jsecurity.session;

import java.io.Serializable;

/**
 * Exception thrown when attempting to interact with the system under the pretense of a
 * particular session (e.g. under a specific session id), and that session does not exist in
 * the system.
 *
 * @since 1.0
 * @author Les Hazlewood
 */
public class UnknownSessionException extends InvalidSessionException {

    public UnknownSessionException() {
        super();
    }

    public UnknownSessionException( String s ) {
        super( s );
    }

    public UnknownSessionException( Throwable cause ) {
        super( cause );
    }

    public UnknownSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    public UnknownSessionException( Serializable sessionId ) {
        super( sessionId );
    }

    public UnknownSessionException( String message, Serializable sessionId ) {
        super( message, sessionId );
    }

    public UnknownSessionException( String message, Throwable cause, Serializable sessionId ) {
        super( message, cause, sessionId );
    }
}
