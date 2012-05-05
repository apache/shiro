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
package org.apache.shiro.session.mgt;

/**
 * @since 1.3
 */
public interface UpdateDeferrable {

    /**
     * Returns {@code true} if modifications that require persistence (updates) can be deferred until a future time,
     * for example, at the end of a request or method invocation.  Returns {@code false} if update operations must
     * be relayed immediately to the backing data store as they occur.
     * <p/>
     * This interface corresponds only to updates; create and delete operations will always be immediately relayed
     * to the underlying data store.
     * <p/>
     * A {@code true} value reduces the number of times the backing data store (such as a cache or database) must be
     * accessed during particular scope (e.g. request or thread).  A {@code false} value indicates that the backing
     * data store will handle updates immediately, probably because it has its own caching mechanism in place to limit
     * data store round trips.  For example, if the data store had a built-in first level cache with a pluggable
     * second-level cache).
     * <p/>
     * For Shiro 1.3 and later, the default value is {@code true}.  Setting this to {@code false} reverts to Shiro
     * 1.2 and earlier behavior, but expects the backing datastore to handle many reads/writes during a single
     * request or invocation.
     *
     * @return {@code true} if state modifications during the course of a request or invocation can be persisted at the
     *         end of a request/invocation, or {@code false} if session modifications must be immediately relayed to
     *         backing data store as they occur.
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-317">SHIRO-317</a>
     * @since 1.3
     */
    boolean isUpdateDeferred();

    void setUpdateDeferred(boolean deferred);
}
