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
import org.apache.shiro.util.Assert;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @since 2.0
 */
public class DefaultCompositeAccountId implements CompositeAccountId {

    private Map<String,AccountId> REALM_ACCOUNTIDS = new LinkedHashMap<String,AccountId>();

    public AccountId getRealmAccountId(String realmName) {
        return realmName != null ? REALM_ACCOUNTIDS.get(realmName) : null;
    }

    public void setRealmAccountId(String realmName, AccountId accountId) {
        Assert.hasText(realmName, "realmName must have text.");
        Assert.notNull(accountId, "accountId cannot be null.");
        REALM_ACCOUNTIDS.put(realmName, accountId);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof DefaultCompositeAccountId) {
            DefaultCompositeAccountId impl = (DefaultCompositeAccountId)o;
            return REALM_ACCOUNTIDS.equals(impl.REALM_ACCOUNTIDS);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return REALM_ACCOUNTIDS.isEmpty() ? 0 : REALM_ACCOUNTIDS.hashCode();
    }

    @Override
    public String toString() {
        if (REALM_ACCOUNTIDS.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for(String realmName : REALM_ACCOUNTIDS.keySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(realmName).append(": ").append(REALM_ACCOUNTIDS.get(realmName));
        }
        return sb.toString();
    }
}
