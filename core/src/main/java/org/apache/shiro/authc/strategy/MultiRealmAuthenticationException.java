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
package org.apache.shiro.authc.strategy;

import org.apache.shiro.authc.AuthenticationException;

import java.util.Collections;
import java.util.Map;

/**
 * @since 2.0
 */
public class MultiRealmAuthenticationException extends AuthenticationException {

    private final Map<String, Throwable> realmErrors;

    public MultiRealmAuthenticationException(Map<String, Throwable> realmErrors) {
        super("Multiple authentication problems across various realms.  " +
                "Only the first discovered exception will be shown as the cause; call getRealmExceptions() " +
                "to access all of them.", realmErrors.values().iterator().next());
        this.realmErrors = Collections.unmodifiableMap(realmErrors);
    }

    public Map<String, Throwable> getRealmExceptions() {
        return this.realmErrors;
    }
}
