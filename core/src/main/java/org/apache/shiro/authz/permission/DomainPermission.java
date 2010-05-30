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

import org.apache.shiro.util.StringUtils;

/**
 * Provides a base Permission class from which type-safe/domain-specific subclasses may extend.  Can be used
 * as a base class for JPA/Hibernate persisted permissions that wish to store the parts of the permission string
 * in separate columns (e.g. 'domain', 'actions' and 'targets' columns), which can be used in querying
 * strategies.
 *
 * @since 1.0
 */
public abstract class DomainPermission extends WildcardPermission {

    private String domain;
    private String actions;
    private String targets;

    /**
     * Creates a domain permission with *all* actions for *all* targets;
     */
    public DomainPermission() {
        setParts(getDomain(getClass()), null, null);
    }

    public DomainPermission(String actions) {
        setParts(getDomain(getClass()), actions, null);
    }

    public DomainPermission(String actions, String targets) {
        setParts(getDomain(getClass()), actions, targets);
    }

    protected void setParts(String domain, String actions, String targets) {
        if (!StringUtils.hasText(domain)) {
            throw new IllegalArgumentException("domain argument cannot be null or empty.");
        }
        StringBuilder sb = new StringBuilder(domain);

        if (!StringUtils.hasText(actions)) {
            if (StringUtils.hasText(targets)) {
                sb.append(PART_DIVIDER_TOKEN).append(WILDCARD_TOKEN);
            }
        } else {
            sb.append(PART_DIVIDER_TOKEN).append(actions);
        }
        if (targets != null) {
            sb.append(PART_DIVIDER_TOKEN).append(targets);
        }
        setParts(sb.toString());
    }

    protected String getDomain(Class<? extends DomainPermission> clazz) {
        String domain = clazz.getSimpleName().toLowerCase();
        //strip any trailing 'permission' text from the name (as all subclasses should have been named):
        int index = domain.lastIndexOf("permission");
        if (index != -1) {
            domain = domain.substring(0, index);
        }
        return domain;
    }

    public String getDomain() {
        return domain;
    }

    protected void setDomain(String domain) {
        this.domain = domain;
    }

    public String getActions() {
        return actions;
    }

    protected void setActions(String actions) {
        this.actions = actions;
    }

    public String getTargets() {
        return targets;
    }

    protected void setTargets(String targets) {
        this.targets = targets;
    }
}
