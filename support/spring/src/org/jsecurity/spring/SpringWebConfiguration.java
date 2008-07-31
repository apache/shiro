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
package org.jsecurity.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.JSecurityException;
import org.jsecurity.mgt.RealmSecurityManager;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.web.config.IniWebConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;
import java.util.Collection;
import java.util.Map;

/**
 * <p>JSecurity configuration that relies on Spring to define and initialize the JSecurity SecurityManager
 * instance (and all of its dependencies) and makes it avaialble to this filter by performing a Spring bean
 * lookup.  The URL/filter behavior is still loaded according to the behavior of the parent class
 * {@link org.jsecurity.web.config.IniWebConfiguration}</p>
 *
 * <p>The behavior used by this filter is as follow:
 * <ol>
 * <li>If a 'securityManagerBeanName' init-param is set, retrieve that sec manager from Spring.</li>
 * <li>if not, look for beans of type {@link SecurityManager} - if there is one instance, use that.
 * If more than one exist, use the one named "securityManager".  If none of them are named "securityManager"
 * throw an exception that says you have to set the init-param to specify the bean name.</li>
 * <li>if no beans of type {@link SecurityManager}, look for any beans of type {@link Realm}.
 * If some are found, create a security manager by calling
 * {@link org.jsecurity.web.config.IniWebConfiguration#createSecurityManager(java.util.Map) super.createSecurityManager(Map)}
 * and set the Realms on the default security manager returned.</li>
 * <li>if none of the above, throw an exception that explains the options.</li>
 * <ol>
 * </p>
 *
 * @author Jeremy Haile
 * @see IniWebConfiguration
 * @since 0.9
 */
public class SpringWebConfiguration extends IniWebConfiguration {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";
    public static final String DEFAULT_SECURITY_MANAGER_BEAN_ID = "securityManager";

    private static final Log log = LogFactory.getLog(SpringWebConfiguration.class);    

    protected String securityManagerBeanName;

    public String getSecurityManagerBeanName() {
        return securityManagerBeanName;
    }

    public void setSecurityManagerBeanName(String securityManagerBeanName) {
        this.securityManagerBeanName = securityManagerBeanName;
    }

    public SpringWebConfiguration() {
    }

    @Override
    public void init() throws JSecurityException {
        String beanName = getFilterConfig().getInitParameter(SECURITY_MANAGER_BEAN_NAME_PARAM_NAME);
        if (beanName != null) {
            setSecurityManagerBeanName(beanName);
        }

        super.init();
    }

    @Override
    protected SecurityManager createDefaultSecurityManager() {
        return createSecurityManager(null);
    }

    @Override
    protected SecurityManager createSecurityManager(Map<String, Map<String, String>> sections) {
        ServletContext servletContext = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
        return getOrCreateSecurityManager(appCtx, sections);
    }

    protected SecurityManager getOrCreateSecurityManager(ApplicationContext appCtx, Map<String, Map<String, String>> sections) {
        String beanName = getSecurityManagerBeanName();

        SecurityManager securityManager = null;
        if (beanName != null) {
            securityManager = (SecurityManager) appCtx.getBean(beanName, SecurityManager.class);
        }

        if (securityManager == null) {
            securityManager = getSecurityManagerByType(appCtx);
        }

        if (securityManager == null) {
            securityManager = createDefaultSecurityManagerFromRealms(appCtx, sections);
        }

        if (securityManager == null) {
            String msg = "Unable to locate a " + SecurityManager.class.getName() + " instance in the " +
                    "Spring WebApplicationContext.  You can 1) simply just define the securityManager as a bean (" +
                    "it will be automatically located based on type) or " +
                    "2) explicitly specifify which bean is retrieved by setting this filter's " +
                    "'securityManagerBeanName' init-param or 3) define one or more " + Realm.class.getName() +
                    " instances and a default SecurityManager using those realms will be created automatically.";
            throw new ApplicationContextException(msg);
        }
        return securityManager;
    }

    @SuppressWarnings("unchecked")
    protected SecurityManager createDefaultSecurityManagerFromRealms(ApplicationContext appCtx, Map<String, Map<String, String>> sections) {
        SecurityManager securityManager = null;

        Map<String, Realm> realmMap = appCtx.getBeansOfType(Realm.class);
        if (realmMap == null || realmMap.isEmpty()) {
            return null;
        }

        Collection<Realm> realms = realmMap.values();
        if (realms == null || realms.isEmpty()) {
            return null;
        }

        if (!realms.isEmpty()) {

            // Create security manager according to superclass and set realms on it from Spring.
            securityManager = super.createSecurityManager(sections);

            if (securityManager instanceof RealmSecurityManager) {
                RealmSecurityManager realmSM = (RealmSecurityManager) securityManager;
                realmSM.setRealms(realms);
            } else {
                log.warn("Attempted to set realms declared in Spring on SecurityManager, but was not of " +
                        "type RealmSecurityManager - instead was of type: " + securityManager.getClass().getName());
            }
        }

        return securityManager;
    }

    @SuppressWarnings("unchecked")
    protected SecurityManager getSecurityManagerByType(ApplicationContext appCtx) {

        SecurityManager securityManager = null;

        Map<String, SecurityManager> securityManagers = appCtx.getBeansOfType(SecurityManager.class);
        if (securityManagers == null || securityManagers.isEmpty()) {
            return null;
        }

        if (securityManagers.size() > 1) {

            // If more than one are declared, see if one is named "securityManager"
            securityManager = securityManagers.get(DEFAULT_SECURITY_MANAGER_BEAN_ID);

            if (securityManager == null) {
                String msg = "There is more than one bean of type " + SecurityManager.class.getName() + " available in the " +
                        "Spring WebApplicationContext.  Please specify which bean should be used by " +
                        "setting this filter's 'securityManagerBeanName' init-param or by naming one of the " +
                        "security managers '" + DEFAULT_SECURITY_MANAGER_BEAN_ID + "'.";
                throw new ApplicationContextException(msg);
            }

        } else if (securityManagers.size() == 1) {

            securityManager = securityManagers.values().iterator().next();
        }

        return securityManager;
    }

}
