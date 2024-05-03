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
import org.junit.jupiter.api.Test;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.easymock.EasyMock.createNiceMock;
import static org.junit.jupiter.api.Assertions.assertNotSame;

/**
 * Test case for the {@link SimpleNamedFilterList} implementation.
 *
 * @since 1.0
 */
public class SimpleNamedFilterListTest {

    @Test
    void testNewInstance() {
        @SuppressWarnings({"MismatchedQueryAndUpdateOfCollection"})
        SimpleNamedFilterList list = new SimpleNamedFilterList("test");
        assertThat(list.getName()).isNotNull();
        assertThat(list.getName()).isEqualTo("test");
    }

    @Test
    void testNewInstanceNameless() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new SimpleNamedFilterList(null);
        });
    }

    @Test
    void testNewInstanceBackingList() {
        new SimpleNamedFilterList("test", new ArrayList<Filter>());
    }

    @Test
    void testNewInstanceNullBackingList() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> {
            new SimpleNamedFilterList("test", null);
        });
    }

    /**
     * Exists mainly to increase code coverage as the SimpleNamedFilterList
     * implementation is a direct pass through.
     */
    @SuppressWarnings("checkstyle:MethodLength")
    @Test
    void testListMethods() {
        FilterChain mock = createNiceMock(FilterChain.class);
        Filter filter = createNiceMock(Filter.class);

        NamedFilterList list = new SimpleNamedFilterList("test");
        list.add(filter);
        FilterChain chain = list.proxy(mock);
        assertThat(chain).isNotNull();
        assertNotSame(mock, chain);

        Filter singleFilter = new SslFilter();
        List<? extends Filter> multipleFilters = CollectionUtils.asList(new PortFilter(), new UserFilter());

        list.add(0, singleFilter);
        assertThat(list).hasSize(2);
        assertThat(list.get(0) instanceof SslFilter).isTrue();
        assertThat(list.toArray()).containsExactly(new Object[]{singleFilter, filter});

        list.addAll(multipleFilters);
        assertThat(list).hasSize(4);
        assertThat(list.get(2) instanceof PortFilter).isTrue();
        assertThat(list.get(3) instanceof UserFilter).isTrue();

        list.addAll(0, CollectionUtils.asList(new PermissionsAuthorizationFilter(), new RolesAuthorizationFilter()));
        assertThat(list).hasSize(6);
        assertThat(list.get(0) instanceof PermissionsAuthorizationFilter).isTrue();
        assertThat(list.get(1) instanceof RolesAuthorizationFilter).isTrue();
        assertThat(list.indexOf(singleFilter)).isEqualTo(2);
        assertThat(list.subList(4, list.size())).isEqualTo(multipleFilters);

        assertThat(list).contains(singleFilter);
        assertThat(list).containsAll(multipleFilters);

        assertThat(list).isNotEmpty();
        list.clear();
        assertThat(list).isEmpty();

        list.add(singleFilter);
        Iterator i = list.iterator();
        assertThat(i.hasNext()).isTrue();
        assertThat(singleFilter).isEqualTo(i.next());

        ListIterator li = list.listIterator();
        assertThat(li.hasNext()).isTrue();
        assertThat(singleFilter).isEqualTo(li.next());

        li = list.listIterator(0);
        assertThat(li.hasNext()).isTrue();
        assertThat(singleFilter).isEqualTo(li.next());

        list.set(0, singleFilter);
        assertThat(singleFilter).isEqualTo(list.get(0));

        Filter[] filters = new Filter[list.size()];
        filters = list.toArray(filters);
        assertThat(filters.length).isEqualTo(1);
        assertThat(singleFilter).isEqualTo(filters[0]);

        assertThat(list.lastIndexOf(singleFilter)).isEqualTo(0);

        list.remove(singleFilter);
        assertThat(list).isEmpty();

        list.add(singleFilter);
        list.remove(0);
        assertThat(list).isEmpty();

        list.add(singleFilter);
        list.addAll(multipleFilters);
        assertThat(list).hasSize(3);
        list.removeAll(multipleFilters);
        assertThat(list).hasSize(1);
        assertThat(singleFilter).isEqualTo(list.get(0));

        list.addAll(multipleFilters);
        assertThat(list).hasSize(3);
        list.retainAll(multipleFilters);
        assertThat(list).hasSize(2);
        assertThat(multipleFilters).isEqualTo(new ArrayList<>(list));
    }
}
