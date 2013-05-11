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

import com.google.common.base.Function;
import com.google.common.collect.Iterators;
import com.google.inject.Injector;
import com.google.inject.Key;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Map;

class SimpleFilterChainResolver implements FilterChainResolver {
    private final Map<String, Key<? extends Filter>[]> chains;
    private final Injector injector;
    private final PatternMatcher patternMatcher;

    SimpleFilterChainResolver(Map<String, Key<? extends Filter>[]> chains, Injector injector, PatternMatcher patternMatcher) {
        this.chains = chains;
        this.injector = injector;
        this.patternMatcher = patternMatcher;
    }

    public FilterChain getChain(ServletRequest request, ServletResponse response, final FilterChain originalChain) {
        String path = WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
        for (final String pathPattern : chains.keySet()) {
            if (patternMatcher.matches(pathPattern, path)) {
                return new SimpleFilterChain(originalChain, Iterators.transform(Iterators.forArray(chains.get(pathPattern)),
                        new Function<Key<? extends Filter>, Filter>() {
                            public Filter apply(Key<? extends Filter> input) {
                                return injector.getInstance(input);
                            }
                        }));
            }
        }
        return null;
    }

}
