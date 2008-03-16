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
package org.jsecurity.authc.pam;

import org.jsecurity.authc.AuthenticationException;

/**
 * Exception thrown during the authentication process when an
 * {@link org.jsecurity.authc.AuthenticationToken AuthenticationToken} implementation is encountered that is not
 * supported by one or more configured {@link org.jsecurity.realm.Realm Realm}s.
 *
 * @see ModularAuthenticationStrategy
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class UnsupportedTokenException extends AuthenticationException {

    /**
     * Creates a new UnsupportedTokenException.
     */
    public UnsupportedTokenException() {
        super();
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param message the reason for the exception
     */
    public UnsupportedTokenException( String message ) {
        super( message );
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnsupportedTokenException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnsupportedTokenException( String message, Throwable cause ) {
        super( message, cause );
    }
}
