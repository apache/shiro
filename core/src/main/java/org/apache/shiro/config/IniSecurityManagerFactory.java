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
package org.apache.shiro.config;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.RealmFactory;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.LifecycleUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * A {@link Factory} that creates {@link SecurityManager} instances based on {@link Ini} configuration.
 *
 * @author The Apache Shiro Project (shiro-dev@incubator.apache.org)
 * @since 1.0
 */
public class IniSecurityManagerFactory extends IniFactorySupport<SecurityManager> {

    public static final String MAIN_SECTION_NAME = "main";

    private static transient final Logger log = LoggerFactory.getLogger(IniSecurityManagerFactory.class);

    /**
     * Creates a new instance.  See the {@link #createInstance()} JavaDoc for detailed explaination of how an INI
     * source will be resolved to use to build the instance.
     */
    public IniSecurityManagerFactory() {
        super();
    }

    public IniSecurityManagerFactory(Ini config) {
        super(config);
    }

    protected SecurityManager createInstance(Ini ini) {
        if (isEmpty(ini)) {
            throw new NullPointerException("Ini argument cannot be null or empty.");
        }
        SecurityManager securityManager = doCreateSecurityManager(ini);
        if (securityManager == null) {
            String msg = SecurityManager.class + " instance cannot be null.";
            throw new ConfigurationException(msg);
        }
        return securityManager;
    }

    protected SecurityManager createDefaultInstance() {
        return new DefaultSecurityManager();
    }

    protected SecurityManager doCreateSecurityManager(Ini ini) {
        Ini.Section mainSection = ini.getSection(MAIN_SECTION_NAME);
        if (CollectionUtils.isEmpty(mainSection)) {
            //try the default:
            mainSection = ini.getSection(Ini.DEFAULT_SECTION_NAME);
        }
        SecurityManager securityManager;
        if (CollectionUtils.isEmpty(mainSection)) {
            if (log.isInfoEnabled()) {
                log.info("No main/default section was found in INI resource [" + ini + "].  A simple default " +
                        "SecurityManager instance will be created automatically.");
            }
            securityManager = createDefaultInstance();
        } else {
            securityManager = createSecurityManager(mainSection);
        }
        return securityManager;
    }

    @SuppressWarnings({"unchecked"})
    protected SecurityManager createSecurityManager(Ini.Section mainSection) {

        Map<String, Object> defaults = new LinkedHashMap<String, Object>();

        SecurityManager securityManager = createDefaultInstance();
        defaults.put("securityManager", securityManager);

        ReflectionBuilder builder = new ReflectionBuilder(defaults);
        Map<String, Object> objects = builder.buildObjects(mainSection);

        //realms and realm factory might have been created - pull them out first so we can
        //initialize the securityManager:
        List<Realm> realms = new ArrayList<Realm>();

        //iterate over the map entries to pull out the realm factory(s):
        for (Map.Entry<String, Object> entry : objects.entrySet()) {
            String name = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof SecurityManager) {
                securityManager = (SecurityManager) value;
            } else if (value instanceof RealmFactory) {
                RealmFactory factory = (RealmFactory) value;
                LifecycleUtils.init(factory);
                Collection<Realm> factoryRealms = factory.getRealms();
                if (factoryRealms != null && !factoryRealms.isEmpty()) {
                    realms.addAll(factoryRealms);
                }
            } else if (value instanceof Realm) {
                Realm realm = (Realm) value;
                //set the name if null:
                String existingName = realm.getName();
                if (existingName == null || existingName.startsWith(realm.getClass().getName())) {
                    try {
                        builder.applyProperty(realm, "name", name);
                    } catch (Exception ignored) {
                        log.debug("Unable to apply 'name' property value {} to realm {}.", name, realm);
                    }
                }
                realms.add(realm);
            }
        }

        //set them on the SecurityManager
        if (!realms.isEmpty()) {
            if (securityManager instanceof RealmSecurityManager) {
                ((RealmSecurityManager) securityManager).setRealms(realms);
            }
            LifecycleUtils.init(realms);
        }

        return securityManager;
    }
}