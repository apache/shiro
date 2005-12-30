/*
 * Copyright (C) 2005 Les Hazlewood.  All rights reserved.
 *
 * This source code is PROPRIETARY AND CONFIDENTIAL.
 * Reproduction or use in any medium whatsoever is expressly forbidden 
 * without prior written consent by Les Hazlewood.
 */
package org.jsecurity.ri.authz.module;

import org.jsecurity.authz.AuthorizationException;

/**
 * Exception thrown when trying to evaluate a
 * {@link org.jsecurity.authz.annotation.HasPermission HasPermission} annotation's
 * {@link org.jsecurity.authz.annotation.HasPermission#targetPath() targetPath} attribute.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class InvalidTargetPathException extends AuthorizationException {

    /**
     * Creates a new InvalidTargetPathException.
     */
    public InvalidTargetPathException() {
        super();
    }

    /**
     * Constructs a new InvalidTargetPathException.
     *
     * @param message the reason for the exception
     */
    public InvalidTargetPathException( String message ) {
        super( message );
    }

    /**
     * Constructs a new InvalidTargetPathException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidTargetPathException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new InvalidTargetPathException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidTargetPathException( String message, Throwable cause ) {
        super( message, cause );
    }
}
