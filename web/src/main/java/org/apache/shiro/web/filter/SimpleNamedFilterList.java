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
package org.apache.shiro.web.filter;

import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.servlet.ProxiedFilterChain;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.util.*;

/**
 * @since 1.0
 */
public class SimpleNamedFilterList implements NamedFilterList {

    private String name;
    private List<Filter> backingList;

    public SimpleNamedFilterList(String name) {
        this.backingList = new ArrayList<Filter>();
        setName(name);
    }

    protected void setName(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Cannot specify an empty name.");
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public FilterChain proxy(FilterChain orig) {
        return new ProxiedFilterChain(orig, this);
    }

    public boolean add(Filter filter) {
        return this.backingList.add(filter);
    }

    public void add(int index, Filter filter) {
        this.backingList.add(index, filter);
    }

    public boolean addAll(Collection<? extends Filter> c) {
        return this.backingList.addAll(c);
    }

    public boolean addAll(int index, Collection<? extends Filter> c) {
        return this.backingList.addAll(index, c);
    }

    public void clear() {
        this.backingList.clear();
    }

    public boolean contains(Object o) {
        return this.backingList.contains(o);
    }

    public boolean containsAll(Collection<?> c) {
        return this.backingList.containsAll(c);
    }

    public Filter get(int index) {
        return this.backingList.get(index);
    }

    public int indexOf(Object o) {
        return this.backingList.indexOf(o);
    }

    public boolean isEmpty() {
        return this.backingList.isEmpty();
    }

    public Iterator<Filter> iterator() {
        return this.backingList.iterator();
    }

    public int lastIndexOf(Object o) {
        return this.backingList.lastIndexOf(o);
    }

    public ListIterator<Filter> listIterator() {
        return this.backingList.listIterator();
    }

    public ListIterator<Filter> listIterator(int index) {
        return this.backingList.listIterator(index);
    }

    public Filter remove(int index) {
        return this.backingList.remove(index);
    }

    public boolean remove(Object o) {
        return this.backingList.remove(o);
    }

    public boolean removeAll(Collection<?> c) {
        return this.backingList.removeAll(c);
    }

    public boolean retainAll(Collection<?> c) {
        return this.backingList.retainAll(c);
    }

    public Filter set(int index, Filter filter) {
        return this.backingList.set(index, filter);
    }

    public int size() {
        return this.backingList.size();
    }

    public List<Filter> subList(int fromIndex, int toIndex) {
        return this.backingList.subList(fromIndex, toIndex);
    }

    public Object[] toArray() {
        return this.backingList.toArray();
    }

    public <T> T[] toArray(T[] a) {
        //noinspection SuspiciousToArrayCall
        return this.backingList.toArray(a);
    }
}
