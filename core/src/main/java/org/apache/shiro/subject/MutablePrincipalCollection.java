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
package org.apache.shiro.subject;

import java.util.Collection;


/**
 * A {@link PrincipalCollection} that allows modification.
 *
 * @since 0.9
 */
public interface MutablePrincipalCollection extends PrincipalCollection {

    /**
     * Adds the given principal to this collection.
     *
     * @param principal the principal to be added.
     * @param realmName the realm this principal came from.
     */
    void add(Object principal, String realmName);

    /**
     * Adds all of the principals in the given collection to this collection.
     *
     * @param principals the principals to be added.
     * @param realmName  the realm these principals came from.
     */
    void addAll(Collection principals, String realmName);

    /**
     * Adds all of the principals from the given principal collection to this collection.
     *
     * @param principals the principals to add.
     */
    void addAll(PrincipalCollection principals);

    /**
     * Removes all Principals in this collection.
     */
    void clear();
}
