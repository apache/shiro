/**
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.isis.security.shiro.permrolemapper;

import java.util.List;
import java.util.Map;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Maps.EntryTransformer;

import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.PermissionUtils;

public class PermissionToRoleMapperFromIni implements PermissionToRoleMapper {

    private final Map<String, List<String>> permissionsByRole;

    /**
     * Using the same logic as in {@link IniRealm}.
     */
    public PermissionToRoleMapperFromIni(Ini ini) {
        Map<String,String> section = ini.getSection(IniRealm.ROLES_SECTION_NAME);
        this.permissionsByRole = Maps.transformEntries(section, new EntryTransformer<String,String,List<String>>() {
            
            public List<String> transformEntry(String key, String value) {
                return Lists.newArrayList(PermissionUtils.toPermissionStrings(value));
            }
        });
    }

    public Map<String, List<String>> getPermissionsByRole() {
        return permissionsByRole;
    }
}
