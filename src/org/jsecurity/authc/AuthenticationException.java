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
package org.jsecurity.authc;

import org.jsecurity.JSecurityException;

/**
 * General exception thrown due to an error during the Authentication process.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class AuthenticationException extends JSecurityException {

    /**
     * Creates a new AuthenticationException.
     */
    public AuthenticationException() {
        super();
    }

    /**
     * Constructs a new AuthenticationException.
     * @param message the reason for the exception
     */
    public AuthenticationException( String message ) {
        super( message );
    }

    /**
     * Constructs a new AuthenticationException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public AuthenticationException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new AuthenticationException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public AuthenticationException( String message, Throwable cause ) {
        super( message, cause );
    }
}
