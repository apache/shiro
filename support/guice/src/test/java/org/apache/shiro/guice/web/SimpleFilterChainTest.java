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

import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.easymock.Capture;
import org.easymock.IMocksControl;
import org.junit.jupiter.api.Test;

import static org.easymock.EasyMock.and;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createStrictControl;
import static org.easymock.EasyMock.same;

public class SimpleFilterChainTest {
    @Test
    void testDoFilter() throws Exception {
        IMocksControl ctrl = createStrictControl();

        FilterChain originalChain = ctrl.createMock(FilterChain.class);
        Filter filter1 = ctrl.createMock("filter1", Filter.class);
        Filter filter2 = ctrl.createMock("filter2", Filter.class);

        ServletRequest request = ctrl.createMock(ServletRequest.class);
        ServletResponse response = ctrl.createMock(ServletResponse.class);

        Capture<FilterChain> fc1 = Capture.newInstance();
        Capture<FilterChain> fc2 = Capture.newInstance();
        filter1.doFilter(same(request), same(response), and(anyObject(FilterChain.class), capture(fc1)));
        filter2.doFilter(same(request), same(response), and(anyObject(FilterChain.class), capture(fc2)));
        originalChain.doFilter(request, response);

        ctrl.replay();

        SimpleFilterChain underTest = new SimpleFilterChain(originalChain, Arrays.asList(filter1, filter2).iterator());

        // all we actually care about is that, if we keep calling the filter chain, everything is called in the right
        // order - we don't care what fc actually contains
        underTest.doFilter(request, response);
        fc1.getValue().doFilter(request, response);
        fc2.getValue().doFilter(request, response);

        ctrl.verify();
    }
}
