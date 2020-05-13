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
package org.apache.shiro.realm.text;

import org.apache.shiro.config.Ini;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link org.apache.shiro.realm.Realm Realm} implementation that creates
 * {@link org.apache.shiro.authc.SimpleAccount SimpleAccount} instances based on
 * {@link Ini} configuration.
 * <p/>
 * This implementation looks for two {@link Ini.Section sections} in the {@code Ini} configuration:
 * <pre>
 * [users]
 * # One or more {@link org.apache.shiro.realm.text.TextConfigurationRealm#setUserDefinitions(String) user definitions}
 * ...
 * [roles]
 * # One or more {@link org.apache.shiro.realm.text.TextConfigurationRealm#setRoleDefinitions(String) role definitions}</pre>
 * <p/>
 * This class also supports setting the {@link #setResourcePath(String) resourcePath} property to create account
 * data from an .ini resource.  This will only be used if there isn't already account data in the Realm.
 *
 * @since 1.0
 */
public class IniRealm extends TextConfigurationRealm {

    public static final String USERS_SECTION_NAME = "users";
    public static final String ROLES_SECTION_NAME = "roles";

    private static transient final Logger log = LoggerFactory.getLogger(IniRealm.class);

    private String resourcePath;
    private Ini ini; //reference added in 1.2 for SHIRO-322

    public IniRealm() {
        super();
    }

    /**
     * This constructor will immediately process the definitions in the {@code Ini} argument.  If you need to perform
     * additional configuration before processing (e.g. setting a permissionResolver, etc), do not call this
     * constructor.  Instead, do the following:
     * <ol>
     * <li>Call the default no-arg constructor</li>
     * <li>Set the Ini instance you wish to use via {@code #setIni}</li>
     * <li>Set any other configuration properties</li>
     * <li>Call {@link #init()}</li>
     * </ol>
     *
     * @param ini the Ini instance which will be inspected to create accounts, groups and permissions for this realm.
     */
    public IniRealm(Ini ini) {
        this();
        processDefinitions(ini);
    }

    /**
     * This constructor will immediately process the definitions in the {@code Ini} resolved from the specified
     * {@code resourcePath}.  If you need to perform additional configuration before processing (e.g. setting a
     * permissionResolver, etc), do not call this constructor.  Instead, do the following:
     * <ol>
     * <li>Call the default no-arg constructor</li>
     * <li>Set the Ini instance you wish to use via {@code #setIni}</li>
     * <li>Set any other configuration properties</li>
     * <li>Call {@link #init()}</li>
     * </ol>
     *
     * @param resourcePath the resource path of the Ini config which will be inspected to create accounts, groups and
     *                     permissions for this realm.
     */
    public IniRealm(String resourcePath) {
        this();
        Ini ini = Ini.fromResourcePath(resourcePath);
        this.ini = ini;
        this.resourcePath = resourcePath;
        processDefinitions(ini);
    }

    public String getResourcePath() {
        return resourcePath;
    }

    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    /**
     * Returns the Ini instance used to configure this realm.  Provided for JavaBeans-style configuration of this
     * realm, particularly useful in Dependency Injection environments.
     * 
     * @return the Ini instance which will be inspected to create accounts, groups and permissions for this realm.
     */
    public Ini getIni() {
        return ini;
    }

    /**
     * Sets the Ini instance used to configure this realm.  Provided for JavaBeans-style configuration of this
     * realm, particularly useful in Dependency Injection environments.
     * 
     * @param ini the Ini instance which will be inspected to create accounts, groups and permissions for this realm.
     */
    public void setIni(Ini ini) {
        this.ini = ini;
    }

    @Override
    protected void onInit() {
        super.onInit();

        // This is an in-memory realm only - no need for an additional cache when we're already
        // as memory-efficient as we can be.
        
        Ini ini = getIni();
        String resourcePath = getResourcePath();
                
        if (!CollectionUtils.isEmpty(this.users) || !CollectionUtils.isEmpty(this.roles)) {
            if (!CollectionUtils.isEmpty(ini)) {
                log.warn("Users or Roles are already populated.  Configured Ini instance will be ignored.");
            }
            if (StringUtils.hasText(resourcePath)) {
                log.warn("Users or Roles are already populated.  resourcePath '{}' will be ignored.", resourcePath);
            }
            
            log.debug("Instance is already populated with users or roles.  No additional user/role population " +
                    "will be performed.");
            return;
        }
        
        if (CollectionUtils.isEmpty(ini)) {
            log.debug("No INI instance configuration present.  Checking resourcePath...");
            
            if (StringUtils.hasText(resourcePath)) {
                log.debug("Resource path {} defined.  Creating INI instance.", resourcePath);
                ini = Ini.fromResourcePath(resourcePath);
                if (!CollectionUtils.isEmpty(ini)) {
                    setIni(ini);
                }
            }
        }
        
        if (CollectionUtils.isEmpty(ini)) {
            String msg = "Ini instance and/or resourcePath resulted in null or empty Ini configuration.  Cannot " +
                    "load account data.";
            throw new IllegalStateException(msg);
        }

        processDefinitions(ini);
    }

    private void processDefinitions(Ini ini) {
        if (CollectionUtils.isEmpty(ini)) {
            log.warn("{} defined, but the ini instance is null or empty.", getClass().getSimpleName());
            return;
        }

        Ini.Section rolesSection = ini.getSection(ROLES_SECTION_NAME);
        if (!CollectionUtils.isEmpty(rolesSection)) {
            log.debug("Discovered the [{}] section.  Processing...", ROLES_SECTION_NAME);
            processRoleDefinitions(rolesSection);
        }

        Ini.Section usersSection = ini.getSection(USERS_SECTION_NAME);
        if (!CollectionUtils.isEmpty(usersSection)) {
            log.debug("Discovered the [{}] section.  Processing...", USERS_SECTION_NAME);
            processUserDefinitions(usersSection);
        } else {
            log.info("{} defined, but there is no [{}] section defined.  This realm will not be populated with any " +
                    "users and it is assumed that they will be populated programatically.  Users must be defined " +
                    "for this Realm instance to be useful.", getClass().getSimpleName(), USERS_SECTION_NAME);
        }
    }
}
