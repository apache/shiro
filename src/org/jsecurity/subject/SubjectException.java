/*
 * Copyright 2005-2008 Jeremy Haile
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
package org.jsecurity.subject;

import org.jsecurity.JSecurityException;

/**
 * <p>Throw when there is an error accessing or interacting with a {@link Subject}.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SubjectException extends JSecurityException {

    /**
     * Creates a new SubjectException.
     */
    public SubjectException() {
        super();
    }

    /**
     * Constructs a new SubjectException.
     * @param message the reason for the exception
     */
    public SubjectException( String message ) {
        super( message );
    }

    /**
     * Constructs a new SubjectException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public SubjectException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new SubjectException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public SubjectException( String message, Throwable cause ) {
        super( message, cause );
    }
}