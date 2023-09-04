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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Singleton;
import com.google.inject.spi.Dependency;
import com.google.inject.spi.ProviderWithDependencies;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;

@Singleton
class FilterChainResolverProvider implements ProviderWithDependencies<FilterChainResolver> {
    @Inject
    Injector injector;

    private final Map<String, Key<? extends Filter>[]> chains;

    private final Set<Dependency<?>> dependencies;

    private PatternMatcher patternMatcher = new AntPathMatcher();

    FilterChainResolverProvider(Map<String, Key<? extends Filter>[]> chains) {
        this.chains = chains;
        Set<Dependency<?>> dependenciesBuilder = new HashSet<Dependency<?>>();
        for (String chain : chains.keySet()) {
            for (Key<? extends Filter> filterKey : chains.get(chain)) {
                dependenciesBuilder.add(Dependency.get(filterKey));
            }
        }
        this.dependencies = Collections.unmodifiableSet(dependenciesBuilder);
    }

    @Inject(optional = true)
    public void setPatternMatcher(PatternMatcher patternMatcher) {
        this.patternMatcher = patternMatcher;
    }

    public Set<Dependency<?>> getDependencies() {
        return dependencies;
    }

    public FilterChainResolver get() {
        return new SimpleFilterChainResolver(chains, injector, patternMatcher);
    }

}
