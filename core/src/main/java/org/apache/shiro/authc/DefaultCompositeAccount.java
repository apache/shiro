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
package org.apache.shiro.authc;

import org.apache.shiro.account.AccountId;
import org.apache.shiro.util.CollectionUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @since 2.0
 */
public class DefaultCompositeAccount implements CompositeAccount {

    // realm name - to - attributes from that realm
    private final Map<String, Map<String, Object>> REALM_ATTRS = new LinkedHashMap<String, Map<String, Object>>();

    private final Map<String, Object> MERGED_ATTRS = new LinkedHashMap<String, Object>();

    private final DefaultCompositeAccountId id;

    private final boolean overwrite;

    public DefaultCompositeAccount() {
        this(true);
    }

    public DefaultCompositeAccount(boolean overwrite) {
        this.overwrite = overwrite;
        this.id = new DefaultCompositeAccountId();
    }

    public AccountId getId() {
        return this.id;
    }

    public Object getCredentials() {
        //not needed: all accounts added to a composite have already been authenticated
        return null;
    }

    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(MERGED_ATTRS);
    }

    public Set<String> getRealmNames() {
        return Collections.unmodifiableSet(REALM_ATTRS.keySet());
    }

    public void appendRealmAccount(String realmName, org.apache.shiro.account.Account account) {

        this.id.setRealmAccountId(realmName, account.getId());

        Map<String, Object> realmAttributes = account.getAttributes();
        if (realmAttributes == null) {
            realmAttributes = Collections.emptyMap();
        }

        REALM_ATTRS.put(realmName, realmAttributes);

        for (String key : realmAttributes.keySet()) {
            if (overwrite) {
                MERGED_ATTRS.put(key, realmAttributes.get(key));
            } else {
                if (!MERGED_ATTRS.containsKey(key)) {
                    MERGED_ATTRS.put(key, realmAttributes.get(key));
                }
            }
        }
    }

    public Map<String, Object> getRealmAttributes(String realmName) {
        Map<String, Object> attrs = REALM_ATTRS.get(realmName);
        if (CollectionUtils.isEmpty(attrs)) {
            return Collections.emptyMap();
        }
        return Collections.unmodifiableMap(attrs);
    }
}
