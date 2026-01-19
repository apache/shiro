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
package org.apache.shiro.guice;

import com.google.inject.Key;
import com.google.inject.OutOfScopeException;
import com.google.inject.Provider;
import com.google.inject.Scope;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

/**
 * Guice scope for Shiro sessions.  Not bound by default.
 */
public class ShiroSessionScope implements Scope {
    public <T> Provider<T> scope(final Key<T> key, final Provider<T> unscoped) {
        return new Provider<T>() {
            public T get() {
                Subject subject = ThreadContext.getSubject();
                if (subject == null) {
                    throw new OutOfScopeException("There is no Shiro Session currently in scope.");
                }
                Session session = subject.getSession();
                T scoped = castSessionAttribute(session);
                if (scoped == null) {
                    scoped = unscoped.get();
                }
                return scoped;
            }

            @SuppressWarnings({"unchecked"})
            private T castSessionAttribute(Session session) {
                return (T) session.getAttribute(key);
            }

            @Override
            public String toString() {
                return unscoped.toString();
            }
        };
    }

    @Override
    public String toString() {
        return "ShiroSessionScope";
    }
}
