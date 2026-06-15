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
package org.apache.shiro.authz.permission;

import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @since 1.3
 */
public class DomainPermissionTest {
    @Test
    void testDefaultConstructor() {
        DomainPermission p;
        List<Set<String>> parts;
        Set<String> set;
        String entry;

        // No arg constructor
        p = new DomainPermission();

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        set = p.getActions();
        assertThat(set).isNull();

        // Verify targets
        set = p.getTargets();
        assertThat(set).isNull();

        // Verify parts
        parts = p.getParts();
        assertThat(parts.size()).as("Number of parts").isEqualTo(1);
        set = parts.get(0);
        assertThat(set).hasSize(1);
        entry = set.iterator().next();
        assertThat(entry).isEqualTo("domain");
    }

    @Test
    void testActionsConstructorWithSingleAction() {
        DomainPermission p;
        List<Set<String>> parts;
        Set<String> set;
        Iterator<String> iterator;
        String entry;

        // Actions constructor with a single action
        p = new DomainPermission("action1");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        set = p.getActions();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");

        // Verify targets
        set = p.getTargets();
        assertThat(set).isNull();

        // Verify parts
        parts = p.getParts();
        assertThat(parts).hasSize(2);
        set = parts.get(0);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("domain");
        set = parts.get(1);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
    }

    @Test
    void testActionsConstructorWithMultipleActions() {
        DomainPermission p;
        List<Set<String>> parts;
        Set<String> set;
        Iterator<String> iterator;
        String entry;

        // Actions constructor with three actions
        p = new DomainPermission("action1,action2,action3");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        set = p.getActions();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action3");

        // Verify targets
        set = p.getTargets();
        assertThat(set).isNull();

        // Verify parts
        parts = p.getParts();
        assertThat(parts).hasSize(2);
        set = parts.get(0);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("domain");
        set = parts.get(1);
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action3");
    }

    @Test
    void testActionsTargetsConstructorWithSingleActionAndTarget() {
        DomainPermission p;
        List<Set<String>> parts;
        Set<String> set;
        Iterator<String> iterator;
        String entry;

        // Actions and target constructor with a single action and target
        p = new DomainPermission("action1", "target1");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        set = p.getActions();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");

        // Verify targets
        set = p.getTargets();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("target1");

        // Verify parts
        parts = p.getParts();
        assertThat(parts).hasSize(3);
        set = parts.get(0);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("domain");
        set = parts.get(1);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
        set = parts.get(2);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("target1");
    }

    @Test
    void testActionsTargetsConstructorWithMultipleActionsAndTargets() {
        DomainPermission p;
        List<Set<String>> parts;
        Set<String> set;
        Iterator<String> iterator;
        String entry;

        // Actions and target constructor with a single action and target
        p = new DomainPermission("action1,action2,action3", "target1,target2,target3");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        set = p.getActions();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action3");

        // Verify targets
        set = p.getTargets();
        assertThat(set).isNotNull();
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("target1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("target2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("target3");

        // Verify parts
        parts = p.getParts();
        assertThat(parts).hasSize(3);
        set = parts.get(0);
        assertThat(set).hasSize(1);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("domain");
        set = parts.get(1);
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("action1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("action3");
        set = parts.get(2);
        assertThat(set).hasSize(3);
        iterator = set.iterator();
        entry = iterator.next();
        assertThat(entry).isEqualTo("target1");
        entry = iterator.next();
        assertThat(entry).isEqualTo("target2");
        entry = iterator.next();
        assertThat(entry).isEqualTo("target3");
    }
}
