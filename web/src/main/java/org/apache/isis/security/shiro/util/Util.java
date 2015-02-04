/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.security.shiro.util;

import java.util.List;
import java.util.Map;

import com.google.common.base.Function;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class Util {

    private static final Function<String, String> TRIM = new Function<String,String>() {
        public String apply(String str) {
            return str.trim();
        }
    };

    public static Map<String, List<String>> parse(String permissionsByRoleStr) {
        Map<String,List<String>> perms = Maps.newHashMap();
        for(String roleAndPermsStr: Splitter.on(";").split(permissionsByRoleStr)) {
            final Iterable<String> split = Splitter.on("=").split(roleAndPermsStr);
            final String[] roleAndPerms = Iterables.toArray(split, String.class);
            if(roleAndPerms.length != 2) {
                continue;
            }
            final String role = roleAndPerms[0].trim();
            final String permStr = roleAndPerms[1].trim();
            perms.put(role, Lists.newArrayList(Iterables.transform(Splitter.on(",").split(permStr), TRIM)));
        }
        return perms;
    }
}
