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
package org.apache.shiro.dao;

/**
 * Root exception indicating invalid or incorrect usage of a data access resource.  This is thrown
 * typically when incorrectly using the resource or its API.
 *
 * @since 1.2
 */
public class InvalidResourceUsageException extends DataAccessException {

    /**
     * Constructs an InvalidResourceUsageException with a message explaining the cause of the exception.
     *
     * @param message the message explaining the cause of the exception
     */
    public InvalidResourceUsageException(String message) {
        super(message);
    }

    /**
     * Constructs a InvalidResourceUsageException with a message explaining the cause of the exception.
     *
     * @param message the explanation
     * @param cause   the root cause of the exception, typically an API-specific exception
     */
    public InvalidResourceUsageException(String message, Throwable cause) {
        super(message, cause);
    }
}
