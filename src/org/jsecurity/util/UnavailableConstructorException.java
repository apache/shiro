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
package org.jsecurity.util;

import org.jsecurity.JSecurityException;

/**
 * Exception thrown when attempting to instantiate a Class via reflection, but a suitable constructor (depending
 * on the number of expected arguments) doesn't exist or cannot be obtained.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class UnavailableConstructorException extends JSecurityException {

    public UnavailableConstructorException() {
        super();
    }

    public UnavailableConstructorException(String message) {
        super(message);
    }

    public UnavailableConstructorException(Throwable cause) {
        super(cause);
    }

    public UnavailableConstructorException(String message, Throwable cause) {
        super(message, cause);
    }
}
