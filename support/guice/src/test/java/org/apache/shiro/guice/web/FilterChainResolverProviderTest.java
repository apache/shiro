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

import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.name.Names;
import com.google.inject.spi.Dependency;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.Filter;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createMock;

/**
 * This test relies on the internal structure of FilterChainResolver in order to check that it got created correctly.
 */
public class FilterChainResolverProviderTest {

    private Map<String, Key<? extends Filter>[]> chains;
    private Key<? extends Filter> key1a;
    private Key<? extends Filter> key1b;
    private Key<? extends Filter> key1c;
    private Key<? extends Filter> key2a;
    private FilterChainResolverProvider underTest;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void setup() {
        chains = new LinkedHashMap<>();

        key1a = Key.get(Filter.class, Names.named("key1a"));
        key1b = Key.get(Filter.class, Names.named("key1b"));
        key1c = Key.get(Filter.class, Names.named("key1c"));
        key2a = Key.get(Filter.class, Names.named("key2a"));

        chains.put("one", new Key[] {key1a, key1b, key1c});
        chains.put("two", new Key[] {key2a});

        underTest = new FilterChainResolverProvider(chains);
    }

    @Test
    @SuppressWarnings("unchecked")
    void testGetDependencies() throws Exception {

        Set<Dependency<?>> dependencySet = underTest.getDependencies();
        assertThat(dependencySet).hasSize(4);

        assertThat(dependencySet.contains(Dependency.get(key1a))).as("Dependency set doesn't contain key1a.").isTrue();
        assertThat(dependencySet.contains(Dependency.get(key1b))).as("Dependency set doesn't contain key1b.").isTrue();
        assertThat(dependencySet.contains(Dependency.get(key1c))).as("Dependency set doesn't contain key1c.").isTrue();
        assertThat(dependencySet.contains(Dependency.get(key2a))).as("Dependency set doesn't contain key2a.").isTrue();
    }


    @Test
    void testGet() throws Exception {

        Injector injector = createMock(Injector.class);
        PatternMatcher patternMatcher = createMock(PatternMatcher.class);

        underTest.injector = injector;
        underTest.setPatternMatcher(patternMatcher);

        FilterChainResolver resolver = underTest.get();

        Field chainsField = SimpleFilterChainResolver.class.getDeclaredField("chains");
        chainsField.setAccessible(true);
        Field injectorField = SimpleFilterChainResolver.class.getDeclaredField("injector");
        injectorField.setAccessible(true);
        Field patternMatcherField = SimpleFilterChainResolver.class.getDeclaredField("patternMatcher");
        patternMatcherField.setAccessible(true);

        assertThat(chainsField.get(resolver)).isSameAs(chains);
        assertThat(injectorField.get(resolver)).isSameAs(injector);
        assertThat(patternMatcherField.get(resolver)).isSameAs(patternMatcher);
    }
}
