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
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.util.Nameable;
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

    public static final String SECURITY_MANAGER_NAME = "securityManager";

    private static transient final Logger log = LoggerFactory.getLogger(IniSecurityManagerFactory.class);

    /**
     * Creates a new instance.  See the {@link #getInstance()} JavaDoc for detailed explaination of how an INI
     * source will be resolved to use to build the instance.
     */
    public IniSecurityManagerFactory() {
        super();
    }

    public IniSecurityManagerFactory(Ini config) {
        super(config);
    }

    protected SecurityManager createInstance(Ini ini) {
        if (CollectionUtils.isEmpty(ini)) {
            throw new NullPointerException("Ini argument cannot be null or empty.");
        }
        SecurityManager securityManager = createSecurityManager(ini);
        if (securityManager == null) {
            String msg = SecurityManager.class + " instance cannot be null.";
            throw new ConfigurationException(msg);
        }
        return securityManager;
    }

    protected SecurityManager createDefaultInstance() {
        return new DefaultSecurityManager();
    }

    protected SecurityManager createSecurityManager(Ini ini) {
        Ini.Section mainSection = ini.getSection(MAIN_SECTION_NAME);
        if (CollectionUtils.isEmpty(mainSection)) {
            //try the default:
            mainSection = ini.getSection(Ini.DEFAULT_SECTION_NAME);
        }
        return doCreateSecurityManager(ini, mainSection);
    }

    private Map<String, Object> buildMainInstances(Ini.Section main) {
        Map<String, Object> defaults = new LinkedHashMap<String, Object>();
        SecurityManager securityManager = createDefaultInstance();
        defaults.put("securityManager", securityManager);
        return buildInstances(main, defaults);
    }

    @SuppressWarnings({"unchecked"})
    protected Map<String, Object> buildInstances(Ini.Section section, Map<String, Object> defaults) {
        ReflectionBuilder builder;
        if (CollectionUtils.isEmpty(defaults)) {
            builder = new ReflectionBuilder();
        } else {
            builder = new ReflectionBuilder(defaults);
        }
        return builder.buildObjects(section);
    }

    private void addToRealms(Collection<Realm> realms, RealmFactory factory) {
        LifecycleUtils.init(factory);
        Collection<Realm> factoryRealms = factory.getRealms();
        if (factoryRealms != null && !factoryRealms.isEmpty()) {
            realms.addAll(factoryRealms);
        }
    }

    private Collection<Realm> getRealms(Map<String, Object> instances) {

        //realms and realm factory might have been created - pull them out first so we can
        //initialize the securityManager:
        List<Realm> realms = new ArrayList<Realm>();

        //iterate over the map entries to pull out the realm factory(s):
        for (Map.Entry<String, Object> entry : instances.entrySet()) {

            String name = entry.getKey();
            Object value = entry.getValue();

            if (value instanceof RealmFactory) {
                addToRealms(realms, (RealmFactory) value);
            } else if (value instanceof Realm) {
                Realm realm = (Realm) value;
                //set the name if null:
                String existingName = realm.getName();
                if (existingName == null || existingName.startsWith(realm.getClass().getName())) {
                    if (realm instanceof Nameable) {
                        ((Nameable) realm).setName(name);
                        log.debug("Applied name '{}' to Nameable realm instance {}", name, realm);
                    } else {
                        log.info("Realm does not implement the {} interface.  Configured name will not be applied.",
                                Nameable.class.getName());
                    }
                }
                realms.add(realm);
            }
        }

        return realms;
    }

    protected void applyRealmsToSecurityManager(Collection<Realm> realms, SecurityManager securityManager) {
        if (!(securityManager instanceof RealmSecurityManager)) {
            String msg = realms.size() + " Realms were configured, but the underlying SecurityManager " +
                    "instance is not a " + RealmSecurityManager.class.getName() + " instance.  This is required " +
                    "to apply any configured Realms.";
            throw new ConfigurationException(msg);
        }
        ((RealmSecurityManager) securityManager).setRealms(realms);
        //initialize the realms now that they have been configured on the security manager
        LifecycleUtils.init(realms);
    }

    /**
     * Returns {@code true} if the Ini contains account data and a {@code Realm} should be implicitly
     * {@link #createRealm(Ini) created} to reflect the account data, {@code false} if no realm should be implicitly
     * created.
     *
     * @param ini the Ini instance to inspect for account data resulting in an implicitly created realm.
     * @return {@code true} if the Ini contains account data and a {@code Realm} should be implicitly
     *         {@link #createRealm(Ini) created} to reflect the account data, {@code false} if no realm should be
     *         implicitly created.
     */
    protected boolean shouldImplicitlyCreateRealm(Ini ini) {
        return !CollectionUtils.isEmpty(ini.getSection(IniRealm.ROLES_SECTION_NAME)) ||
                !CollectionUtils.isEmpty(ini.getSection(IniRealm.USERS_SECTION_NAME));
    }

    /**
     * Creates a {@code Realm} from the Ini instance containing account data.
     *
     * @param ini the Ini instance from which to acquire the account data.
     * @return a new Realm instance reflecting the account data discovered in the {@code Ini}.
     */
    protected Realm createRealm(Ini ini) {
        return new IniRealm(ini);
    }

    @SuppressWarnings({"unchecked"})
    protected SecurityManager doCreateSecurityManager(Ini ini, Ini.Section mainSection) {

        Map<String, Object> objects = buildMainInstances(mainSection);

        SecurityManager securityManager = (SecurityManager) objects.get(SECURITY_MANAGER_NAME);

        //realms and realm factory might have been created - pull them out first so we can
        //initialize the securityManager:
        Collection<Realm> realms = getRealms(objects);

        if (shouldImplicitlyCreateRealm(ini)) {
            Realm realm = createRealm(ini);
            realms.add(realm);
        }

        //set them on the SecurityManager
        if (!CollectionUtils.isEmpty(realms)) {
            applyRealmsToSecurityManager(realms, securityManager);
        }

        return securityManager;
    }
}