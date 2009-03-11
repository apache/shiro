/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ki.subject;

/**
 * Exception thrown when a <tt>Subject</tt> is accessed that has been invalidated.  Usually this occurs
 * when accessing a <tt>Subject</tt> whose {@link Subject#logout()} method
 * has been called.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class InvalidSubjectException extends SubjectException {

    /**
     * Creates a new InvalidSubjectException.
     */
    public InvalidSubjectException() {
        super();
    }

    /**
     * Constructs a new InvalidSubjectException.
     *
     * @param message the reason for the exception
     */
    public InvalidSubjectException(String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidSubjectException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSubjectException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidSubjectException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSubjectException(String message, Throwable cause) {
        super(message, cause);
    }
}
