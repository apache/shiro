/*
 * Copyright (C) 2005 Les Hazlewood.  All rights reserved.
 *
 * This source code is PROPRIETARY AND CONFIDENTIAL.
 * Reproduction or use in any medium whatsoever is expressly forbidden 
 * without prior written consent by Les Hazlewood.
 */
package org.jsecurity.authc;

/**
 * Thrown when attempting to authenticate and the corresponding account has been disabled for
 * some reason.
 *
 * @see LockedAccountException
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class DisabledAccountException extends AccountException {

    /**
     * Creates a new DisabledAccountException.
     */
    public DisabledAccountException() {
        super();
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param message the reason for the exception
     */
    public DisabledAccountException( String message ) {
        super( message );
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public DisabledAccountException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new DisabledAccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public DisabledAccountException( String message, Throwable cause ) {
        super( message, cause );
    }
}
