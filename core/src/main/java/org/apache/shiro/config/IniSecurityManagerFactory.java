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

import org.apache.shiro.io.ResourceUtils;
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
 * A {@link Factory} that creates {@link SecurityManager} instances based on
 * {@link Ini} configuration.
 *
 * @since 1.0
 */
public class IniSecurityManagerFactory implements Factory<SecurityManager> {

    public static final String DEFAULT_INI_RESOURCE_PATH = "classpath:shiro.ini";

    public static final String MAIN_SECTION_NAME = "main";

    private static transient final Logger log = LoggerFactory.getLogger(IniSecurityManagerFactory.class);

    private Ini ini;

    /**
     * Creates a new instance.  See the {@link #createInstance()} JavaDoc for detailed explaination of how an INI
     * source will be resolved to use to build the instance.
     */
    public IniSecurityManagerFactory() {
    }

    public IniSecurityManagerFactory(Ini config) {
        this.ini = config;
    }

    public Ini getIni() {
        return ini;
    }

    public void setIni(Ini ini) {
        this.ini = ini;
    }

    private static boolean isEmpty(Ini ini) {
        return ini == null || ini.isEmpty();
    }

    /**
     * Creates a new {@code SecurityManager} instance by using a configured INI source.  This implementation
     * functions as follows:
     * <ol>
     * <li>The {@code Ini} instance available via the {@link #getIni()} method will be used if available.</li>
     * <li>If {@link #getIni()} is {@code null} empty, this implementation will attempt to find and load a
     * {@code shiro.ini} file at the root of the classpath (i.e. {@code classpath:shiro.ini}) and use the resulting
     * {@link Ini} instance constructed based on that file.</li>
     * <li>If neither of the above two mechanisms result in an {@code Ini} instance, a simple default
     * {@code SecurityManager} instance is returned via the
     * {@link #createDefaultSecurityManager()} method.</li>
     * </ol>
     *
     * @return a new {@code SecurityManager} instance by using a configured INI source.
     */
    public SecurityManager createInstance() {
        Ini ini = getIni();
        if (isEmpty(ini)) {
            log.debug("Null or empty Ini.  Falling back to classpath:/shiro.ini");
            if (ResourceUtils.resourceExists(DEFAULT_INI_RESOURCE_PATH)) {
                log.debug("Found shiro.ini at the root of the classpath.");
                ini = new Ini();
                ini.loadFromPath(DEFAULT_INI_RESOURCE_PATH);
                if (isEmpty(ini)) {
                    log.warn("shiro.ini found at the root of the classpath, but it did not contain any data.");
                }
            }
        }

        SecurityManager securityManager;

        if (!isEmpty(ini)) {
            log.debug("Creating SecurityManager from Ini instance.");
            securityManager = createSecurityManager(ini);
        } else {
            log.debug("No populated Ini instance available.  Creating a default SecurityManager instance.");
            securityManager = createDefaultSecurityManager();
        }

        return securityManager;
    }

    protected final SecurityManager createSecurityManager(Ini ini) {
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

    protected SecurityManager createDefaultSecurityManager() {
        return newSecurityManagerInstance();
    }

    protected RealmSecurityManager newSecurityManagerInstance() {
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
            securityManager = createDefaultSecurityManager();
        } else {
            securityManager = createSecurityManager(mainSection);
        }
        return securityManager;
    }

    @SuppressWarnings({"unchecked"})
    protected SecurityManager createSecurityManager(Ini.Section mainSection) {

        Map<String, Object> defaults = new LinkedHashMap<String, Object>();

        SecurityManager securityManager = createDefaultSecurityManager();
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