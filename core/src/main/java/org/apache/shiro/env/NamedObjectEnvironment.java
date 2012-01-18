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
package org.apache.shiro.env;

/**
 * An environment that supports object lookup by name.
 *
 * @since 1.2
 */
public interface NamedObjectEnvironment extends Environment {

    /**
     * Returns the object in Shiro's environment with the specified name and type or {@code null} if
     * no object with that name was found.
     *
     * @param name the assigned name of the object.
     * @param requiredType the class to which the discovered object must be assignable.
     * @param <T> the type of the class
     * @throws RequiredTypeException if the discovered object does not equal, extend, or implement the specified class.
     * @return the object in Shiro's environment with the specified name (of the specified type) or {@code null} if
     * no object with that name was found.
     */
    <T> T getObject(String name, Class<T> requiredType) throws RequiredTypeException;
}
