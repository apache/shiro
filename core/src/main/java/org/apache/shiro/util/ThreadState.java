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
package org.apache.shiro.util;

/**
 * A {@code ThreadState} instance manages any state that might need to be bound and/or restored during a thread's
 * execution.
 *
 * @since 1.0
 */
public interface ThreadState {

    /**
     * Binds any state that should be made accessible during a thread's execution.
     */
    void bind();

    /**
     * Restores a thread to its state before bind {@link #bind bind} was invoked.
     */
    void restore();

    /**
     * Clears a thread's state modifications entirely.
     */
    void clear();

}
