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

import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.filter.authz.PortFilter;
import org.apache.shiro.web.filter.authz.RolesAuthorizationFilter;
import org.apache.shiro.web.filter.authz.SslFilter;
import org.junit.Test;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.*;

import static org.easymock.EasyMock.createNiceMock;
import static org.junit.Assert.*;

/**
 * Test case for the {@link SimpleNamedFilterList} implementation.
 *
 * @since 1.0
 */
public class SimpleNamedFilterListTest {

    @Test
    public void testNewInstance() {
        @SuppressWarnings({"MismatchedQueryAndUpdateOfCollection"})
        SimpleNamedFilterList list = new SimpleNamedFilterList("test");
        assertNotNull(list.getName());
        assertEquals("test", list.getName());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNewInstanceNameless() {
        new SimpleNamedFilterList(null);
    }

    @Test
    public void testNewInstanceBackingList() {
        new SimpleNamedFilterList("test", new ArrayList<Filter>());
    }

    @Test(expected = NullPointerException.class)
    public void testNewInstanceNullBackingList() {
        new SimpleNamedFilterList("test", null);
    }

    /**
     * Exists mainly to increase code coverage as the SimpleNamedFilterList
     * implementation is a direct pass through.
     */
    @Test
    public void testListMethods() {
        FilterChain mock = createNiceMock(FilterChain.class);
        Filter filter = createNiceMock(Filter.class);

        NamedFilterList list = new SimpleNamedFilterList("test");
        list.add(filter);
        FilterChain chain = list.proxy(mock);
        assertNotNull(chain);
        assertNotSame(mock, chain);

        Filter singleFilter = new SslFilter();
        List<? extends Filter> multipleFilters = CollectionUtils.asList(new PortFilter(), new UserFilter());

        list.add(0, singleFilter);
        assertEquals(2, list.size());
        assertTrue(list.get(0) instanceof SslFilter);
        assertTrue(Arrays.equals(list.toArray(), new Object[]{singleFilter, filter}));

        list.addAll(multipleFilters);
        assertEquals(4, list.size());
        assertTrue(list.get(2) instanceof PortFilter);
        assertTrue(list.get(3) instanceof UserFilter);

        list.addAll(0, CollectionUtils.asList(new PermissionsAuthorizationFilter(), new RolesAuthorizationFilter()));
        assertEquals(6, list.size());
        assertTrue(list.get(0) instanceof PermissionsAuthorizationFilter);
        assertTrue(list.get(1) instanceof RolesAuthorizationFilter);
        assertEquals(2, list.indexOf(singleFilter));
        assertEquals(multipleFilters, list.subList(4, list.size()));

        assertTrue(list.contains(singleFilter));
        assertTrue(list.containsAll(multipleFilters));

        assertFalse(list.isEmpty());
        list.clear();
        assertTrue(list.isEmpty());

        list.add(singleFilter);
        Iterator i = list.iterator();
        assertTrue(i.hasNext());
        assertEquals(i.next(), singleFilter);

        ListIterator li = list.listIterator();
        assertTrue(li.hasNext());
        assertEquals(li.next(), singleFilter);

        li = list.listIterator(0);
        assertTrue(li.hasNext());
        assertEquals(li.next(), singleFilter);

        list.set(0, singleFilter);
        assertEquals(list.get(0), singleFilter);

        Filter[] filters = new Filter[list.size()];
        filters = list.toArray(filters);
        assertEquals(1, filters.length);
        assertEquals(filters[0], singleFilter);

        assertEquals(0, list.lastIndexOf(singleFilter));

        list.remove(singleFilter);
        assertTrue(list.isEmpty());

        list.add(singleFilter);
        list.remove(0);
        assertTrue(list.isEmpty());

        list.add(singleFilter);
        list.addAll(multipleFilters);
        assertEquals(3, list.size());
        list.removeAll(multipleFilters);
        assertEquals(1, list.size());
        assertEquals(list.get(0), singleFilter);

        list.addAll(multipleFilters);
        assertEquals(3, list.size());
        list.retainAll(multipleFilters);
        assertEquals(2, list.size());
        //noinspection unchecked
        assertEquals(new ArrayList(list), multipleFilters);
    }


}
