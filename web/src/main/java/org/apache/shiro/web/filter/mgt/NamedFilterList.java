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
package org.apache.shiro.web.filter.mgt;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.List;

/**
 * A {@code NamedFilterList} is a {@code List} of {@code Filter} instances that is uniquely identified by a
 * {@link #getName() name}.  It has the ability to generate new {@link FilterChain} instances reflecting this list's
 * filter order via the {@link #proxy proxy} method.
 *
 * @since 1.0
 */
public interface NamedFilterList extends List<Filter> {

    /**
     * Returns the configuration-unique name assigned to this {@code Filter} list.
     *
     * @return the configuration-unique name assigned to this {@code Filter} list.
     */
    String getName();

    /**
     * Returns a new {@code FilterChain} instance that will first execute this list's {@code Filter}s (in list order)
     * and end with the execution of the given {@code filterChain} instance.
     *
     * @param filterChain the {@code FilterChain} instance to execute after this list's {@code Filter}s have executed.
     * @return a new {@code FilterChain} instance that will first execute this list's {@code Filter}s (in list order)
     *         and end with the execution of the given {@code filterChain} instance.
     */
    FilterChain proxy(FilterChain filterChain);
}
