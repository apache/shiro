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

import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.servlet.ProxiedFilterChain;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

/**
 * Simple {@code NamedFilterList} implementation that is supported by a backing {@link List} instance and a simple
 * {@link #getName() name} property. All {@link List} method implementations are immediately delegated to the
 * wrapped backing list.
 *
 * @since 1.0
 */
public class SimpleNamedFilterList implements NamedFilterList {

    private String name;
    private List<Filter> backingList;

    /**
     * Creates a new {@code SimpleNamedFilterList} instance with the specified {@code name}, defaulting to a new
     * {@link ArrayList ArrayList} instance as the backing list.
     *
     * @param name the name to assign to this instance.
     * @throws IllegalArgumentException if {@code name} is null or empty.
     */
    public SimpleNamedFilterList(String name) {
        this(name, new ArrayList<Filter>());
    }

    /**
     * Creates a new {@code SimpleNamedFilterList} instance with the specified {@code name} and {@code backingList}.
     *
     * @param name        the name to assign to this instance.
     * @param backingList the list instance used to back all of this class's {@link List} method implementations.
     * @throws IllegalArgumentException if {@code name} is null or empty.
     * @throws NullPointerException     if the backing list is {@code null}.
     */
    public SimpleNamedFilterList(String name, List<Filter> backingList) {
        if (backingList == null) {
            throw new NullPointerException("backingList constructor argument cannot be null.");
        }
        this.backingList = backingList;
        setName(name);
    }

    protected void setName(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Cannot specify a null or empty name.");
        }
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public FilterChain proxy(FilterChain orig) {
        return new ProxiedFilterChain(orig, this);
    }

    @Override
    public boolean add(Filter filter) {
        return this.backingList.add(filter);
    }

    @Override
    public void add(int index, Filter filter) {
        this.backingList.add(index, filter);
    }

    public boolean addAll(Collection<? extends Filter> c) {
        return this.backingList.addAll(c);
    }

    public boolean addAll(int index, Collection<? extends Filter> c) {
        return this.backingList.addAll(index, c);
    }

    @Override
    public void clear() {
        this.backingList.clear();
    }

    @Override
    public boolean contains(Object o) {
        return this.backingList.contains(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return this.backingList.containsAll(c);
    }

    @Override
    public Filter get(int index) {
        return this.backingList.get(index);
    }

    @Override
    public int indexOf(Object o) {
        return this.backingList.indexOf(o);
    }

    @Override
    public boolean isEmpty() {
        return this.backingList.isEmpty();
    }

    @Override
    public Iterator<Filter> iterator() {
        return this.backingList.iterator();
    }

    @Override
    public int lastIndexOf(Object o) {
        return this.backingList.lastIndexOf(o);
    }

    @Override
    public ListIterator<Filter> listIterator() {
        return this.backingList.listIterator();
    }

    @Override
    public ListIterator<Filter> listIterator(int index) {
        return this.backingList.listIterator(index);
    }

    @Override
    public Filter remove(int index) {
        return this.backingList.remove(index);
    }

    @Override
    public boolean remove(Object o) {
        return this.backingList.remove(o);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return this.backingList.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return this.backingList.retainAll(c);
    }

    @Override
    public Filter set(int index, Filter filter) {
        return this.backingList.set(index, filter);
    }

    @Override
    public int size() {
        return this.backingList.size();
    }

    @Override
    public List<Filter> subList(int fromIndex, int toIndex) {
        return this.backingList.subList(fromIndex, toIndex);
    }

    @Override
    public Object[] toArray() {
        return this.backingList.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        //noinspection SuspiciousToArrayCall
        return this.backingList.toArray(a);
    }
}
