/*
 * Copyright (C) 2005 Les Hazlewood.  All rights reserved.
 *
 * This source code is PROPRIETARY AND CONFIDENTIAL.
 * Reproduction or use in any medium whatsoever is expressly forbidden 
 * without prior written consent by Les Hazlewood.
 */
package org.jsecurity.ri.util;

import org.jsecurity.JSecurityException;

/**
 * Thrown internally by the JSecurity RI when dynamically instantiating a Permission
 * class and that instantiation unexpectedly fails.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class PermissionInstantiationException extends JSecurityException {

    /**
     * Creates a new PermissionInstantiationException.
     */
    public PermissionInstantiationException() {
        super();
    }

    /**
     * Constructs a new PermissionInstantiationException.
     *
     * @param message the reason for the exception
     */
    public PermissionInstantiationException( String message ) {
        super( message );
    }

    /**
     * Constructs a new PermissionInstantiationException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public PermissionInstantiationException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new PermissionInstantiationException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public PermissionInstantiationException( String message, Throwable cause ) {
        super( message, cause );
    }
}
