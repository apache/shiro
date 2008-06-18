/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.spring;

import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.jsecurity.web.servlet.JSecurityFilter;
import org.springframework.beans.factory.BeanNotOfRequiredTypeException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;
import java.util.Collection;
import java.util.Map;

/**
 * <p>Relies on Spring to define and initialize the JSecurity SecurityManager instance (and all of its dependencies)
 * and makes it avaialble to this filter by performing a Spring bean lookup.</p>
 * <p/>
 * <p>The behavior used by this filter is as follow:
 * <ol>
 * <li>If a 'securityManagerBeanName' init-param is set, retrieve that sec manager from Spring.</li>
 * <li>if not, look for beans of type {@link SecurityManager} - if there is one instance, use that.
 * If more than one exist, use the one named "securityManager".  If none of them are named "securityManager"
 * throw an exception that says you have to set the init-param to specify the bean name.</li>
 * <li>if no beans of type {@link SecurityManager}, look for any beans of type {@link Realm}.
 * If some are found, create a DefaultSecurityManager and set the Realms on it.</li>
 * <li>if none of the above, throw an exception that explains the options.</li>
 * <ol>
 * </p>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public class SpringJSecurityFilter extends JSecurityFilter {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";
    public static final String DEFAULT_SECURITY_MANAGER_BEAN_ID = "securityManager";

    protected String securityManagerBeanName;

    public String getSecurityManagerBeanName() {
        return securityManagerBeanName;
    }

    public void setSecurityManagerBeanName(String securityManagerBeanName) {
        this.securityManagerBeanName = securityManagerBeanName;
    }

    public void onFilterConfigSet() throws Exception {
        String beanName = getFilterConfig().getInitParameter(SECURITY_MANAGER_BEAN_NAME_PARAM_NAME);
        if (beanName != null) {
            setSecurityManagerBeanName(beanName);
        }
        super.onFilterConfigSet();
    }

    protected SecurityManager getSecurityManager(ApplicationContext appCtx) {
        String beanName = getSecurityManagerBeanName();

        SecurityManager securityManager = null;
        if (beanName != null) {
            securityManager = (SecurityManager) appCtx.getBean(beanName, SecurityManager.class);
        }

        if (securityManager == null) {
            securityManager = getSecurityManagerByType(appCtx);
        }

        if (securityManager == null) {
            securityManager = createDefaultSecurityManagerFromRealms(appCtx);
        }

        if (securityManager == null) {
            String msg = "There is no " + SecurityManager.class.getName() + " instance available in the " +
                    "Spring WebApplicationContext.  A bean of type " + SecurityManager.class.getName() + " would be " +
                    "automatically detected.  You can also specify which bean is retrieved by " +
                    "setting this filter's 'securityManagerBeanName' init-param.";
            throw new ApplicationContextException(msg);
        }
        Object retrieved = appCtx.getBean(beanName);
        if (!(retrieved instanceof SecurityManager)) {
            throw new BeanNotOfRequiredTypeException(beanName, SecurityManager.class, retrieved.getClass());
        }
        return (SecurityManager) retrieved;
    }

    @SuppressWarnings("unchecked")
    private SecurityManager createDefaultSecurityManagerFromRealms(ApplicationContext appCtx) {
        DefaultWebSecurityManager securityManager = null;

        Collection<Realm> realms = appCtx.getBeansOfType(Realm.class).values();
        if (!realms.isEmpty()) {
            securityManager = new DefaultWebSecurityManager();
            securityManager.setRealms(realms);
            securityManager.init();
        }

        return securityManager;
    }

    @SuppressWarnings("unchecked")
    protected SecurityManager getSecurityManagerByType(ApplicationContext appCtx) {

        SecurityManager securityManager = null;

        Map<String, SecurityManager> securityManagers = appCtx.getBeansOfType(SecurityManager.class);

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

    protected org.jsecurity.mgt.SecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext(sc);
        return getSecurityManager(appCtx);
    }

}
