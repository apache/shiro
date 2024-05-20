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
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.util.WebUtils;
import org.easymock.IMocksControl;
import org.junit.jupiter.api.Test;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createStrictControl;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.same;


/**
 * Note that this test is highly dependent on the implementation of SimpleFilterChain.  There's really no way around
 * that I can see.  We determine that the resolver has created it correctly by observing its behavior.
 */
public class SimpleFilterChainResolverTest {

    @Test
    @SuppressWarnings("unchecked")
    void testGetChain() throws Exception {
        // test that it uses the pattern matcher - check
        // test that the FIRST chain found is the one that gets returned - check
        // test that the chain returned actually contains the filters returned by the injector - check
        // test that the keys specified for the chain are requested from the injector - check
        // test that filters are looked up lazily - check

        IMocksControl ctrl = createStrictControl();

        Injector injector = ctrl.createMock(Injector.class);
        Map<String, Key<? extends Filter>[]> chainMap = new LinkedHashMap<String, Key<? extends Filter>[]>();

        final String chainOne = "one";
        final String chainTwo = "two";
        final String chainThree = "three";

        final Key<? extends Filter> key1a = Key.get(Filter.class, Names.named("key1a"));
        final Key<? extends Filter> key1b = Key.get(Filter.class, Names.named("key1b"));
        final Key<? extends Filter> key2a = Key.get(Filter.class, Names.named("key2a"));
        final Key<? extends Filter> key2b = Key.get(Filter.class, Names.named("key2b"));
        final Key<? extends Filter> key3a = Key.get(Filter.class, Names.named("key3a"));
        final Key<? extends Filter> key3b = Key.get(Filter.class, Names.named("key3b"));

        chainMap.put(chainOne, new Key[] {key1a, key1b});
        chainMap.put(chainTwo, new Key[] {key2a, key2b});
        chainMap.put(chainThree, new Key[] {key3a, key3b});

        PatternMatcher patternMatcher = ctrl.createMock(PatternMatcher.class);
        ServletRequest request = ctrl.createMock(HttpServletRequest.class);
        ServletResponse response = ctrl.createMock(HttpServletResponse.class);
        FilterChain originalChain = ctrl.createMock(FilterChain.class);

        expect(request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE)).andReturn("/mychain");
        expect(request.getAttribute(WebUtils.INCLUDE_PATH_INFO_ATTRIBUTE)).andReturn("");

        expect(request.getCharacterEncoding()).andStubReturn(null);

        expect(patternMatcher.matches(chainOne, "/mychain")).andReturn(false);
        expect(patternMatcher.matches(chainTwo, "/mychain")).andReturn(true);

        Filter filter2a = ctrl.createMock(Filter.class);
        Filter filter2b = ctrl.createMock(Filter.class);

        expect((Filter) injector.getInstance(key2a)).andReturn(filter2a);
        filter2a.doFilter(same(request), same(response), anyObject(FilterChain.class));
        expect((Filter) injector.getInstance(key2b)).andReturn(filter2b);
        filter2b.doFilter(same(request), same(response), anyObject(FilterChain.class));
        originalChain.doFilter(request, response);

        ctrl.replay();

        SimpleFilterChainResolver underTest = new SimpleFilterChainResolver(chainMap, injector, patternMatcher);

        FilterChain got = underTest.getChain(request, response, originalChain);

        got.doFilter(request, response);
        got.doFilter(request, response);
        got.doFilter(request, response);

        ctrl.verify();

        ctrl.reset();

        expect(request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE)).andReturn("/nochain");
        expect(request.getAttribute(WebUtils.INCLUDE_PATH_INFO_ATTRIBUTE)).andReturn("");

        expect(request.getCharacterEncoding()).andStubReturn(null);

        expect(patternMatcher.matches(chainOne, "/nochain")).andReturn(false);
        expect(patternMatcher.matches(chainTwo, "/nochain")).andReturn(false);
        expect(patternMatcher.matches(chainThree, "/nochain")).andReturn(false);

        ctrl.replay();

        assertThat(underTest.getChain(request, response, originalChain))
            .as("Expected no chain to match, did not get a null value in return.").isNull();

        ctrl.verify();
    }
}
