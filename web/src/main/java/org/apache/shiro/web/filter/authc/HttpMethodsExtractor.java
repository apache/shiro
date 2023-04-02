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

package org.apache.shiro.web.filter.authc;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class HttpMethodsExtractor {

    public static Set<String> extractHttpMethodsFromOptions(String[] options) {
        Set<String> methods = new HashSet<String>();

        if (options != null) {
            for (String option : options) {
                if (isHttpMethod(option)) {
                    methods.add(option.toUpperCase(Locale.ENGLISH));
                }
            }
        }
        return methods;
    }

    private static boolean isHttpMethod(String option) {
        return !option.equalsIgnoreCase(AuthenticatingFilter.PERMISSIVE);
    }
}
