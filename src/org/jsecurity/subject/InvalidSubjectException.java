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
package org.jsecurity.subject;

/**
 * Exception thrown when a <tt>Subject</tt> is accessed that has been invalidated.  Usually this occurs
 * when accessing a <tt>Subject</tt> whose {@link Subject#logout()} method
 * has been called.  
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class InvalidSubjectException extends SubjectException {

    public InvalidSubjectException() {
        super();
    }

    public InvalidSubjectException( String message ) {
        super( message );
    }

    public InvalidSubjectException( Throwable cause ) {
        super( cause );
    }

    public InvalidSubjectException( String message, Throwable cause ) {
        super( message, cause );
    }
}
