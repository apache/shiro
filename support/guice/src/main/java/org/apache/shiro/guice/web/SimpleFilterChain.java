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
package org.apache.shiro.guice.web;

import javax.servlet.*;
import java.io.IOException;
import java.util.Iterator;

class SimpleFilterChain implements FilterChain {


    private final FilterChain originalChain;
    private final Iterator<? extends Filter> chain;

    private boolean originalCalled = false;

    public SimpleFilterChain(FilterChain originalChain, Iterator<? extends Filter> chain) {
        this.originalChain = originalChain;
        this.chain = chain;
    }

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        if (chain.hasNext()) {
            Filter filter = chain.next();
            filter.doFilter(request, response, this);
        } else if (!originalCalled) {
            originalCalled = true;
            originalChain.doFilter(request, response);
        }
    }

    /**
     * Exposed for testing, not part of public API.
     * @return an Iterator of filters.
     */
    Iterator<? extends Filter> getFilters() {
        return chain;
    }

}
