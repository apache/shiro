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

import com.google.inject.Key;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.junit.jupiter.api.Test;

import jakarta.servlet.Filter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.fail;

public class DefaultFiltersTest {

    @Test
    void checkDefaultFilters() throws Exception {
        EnumSet<DefaultFilter> defaultFilters = EnumSet.allOf(DefaultFilter.class);
        for (Field field : ShiroWebModule.class.getFields()) {
            if (Modifier.isStatic(field.getModifiers()) && Key.class.isAssignableFrom(field.getType())) {
                @SuppressWarnings("unchecked")
                Class<? extends Filter> filterType = ((Key) field.get(null)).getTypeLiteral().getRawType();
                boolean found = false;
                for (DefaultFilter filter : defaultFilters) {
                    if (filterType.equals(filter.getFilterClass())) {
                        found = true;
                        defaultFilters.remove(filter);
                        break;
                    }
                }
                if (!found) {
                    fail("Guice ShiroWebModule contains a default filter that Shiro proper does not. ("
                            + filterType.getName() + ")");
                }
            }
        }
        if (!defaultFilters.isEmpty()) {
            fail("Guice ShiroWebModule is missing one or more filters. " + defaultFilters);
        }
    }

}
