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
package org.apache.shiro.web;

import groovy.lang.Closure;

import java.io.Closeable;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

/**
 * Wrapper that will restore System properties after test methods.
 *
 * Based on: https://github.com/stefanbirkner/system-rules/blob/master/src/main/java/org/junit/contrib/java/lang/system/RestoreSystemProperties.java
 */
public class RestoreSystemProperties implements Closeable {

    private final Properties originalProperties;

    public RestoreSystemProperties() {
        originalProperties = System.getProperties();
        System.setProperties(copyOf(originalProperties));
    }

    public void restore() {
        System.setProperties(originalProperties);
    }

    private Properties copyOf(Properties source) {
        Properties copy = new Properties();
        copy.putAll(source);
        return copy;
    }

    public static <T> T withProperties(Closure<T> closure) {
        return withProperties(Collections.emptyMap(), closure);
    }

    public static <T> T withProperties(Map<String, String> properties, Closure<T> closure) {

        try (RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties()) {
            properties.forEach(System::setProperty);

            return closure.call();
        }
    }

    @Override
    public void close() {
        restore();
    }
}
