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
package org.jsecurity.spring.servlet;

import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.web.servlet.SecurityManagerListener;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SpringSecurityManagerListener extends SecurityManagerListener {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";
    public static final String DEFAULT_SECURITY_MANAGER_BEAN_NAME = "securityManager";

    protected String securityManagerBeanName = DEFAULT_SECURITY_MANAGER_BEAN_NAME;

    public String getSecurityManagerBeanName() {
        return securityManagerBeanName;
    }

    public void setSecurityManagerBeanName( String securityManagerBeanName ) {
        this.securityManagerBeanName = securityManagerBeanName;
    }

    public void init() {
        String beanName = getServletContext().getInitParameter( SECURITY_MANAGER_BEAN_NAME_PARAM_NAME );
        if ( beanName != null ) {
            setSecurityManagerBeanName( beanName );
        }
        super.init();
    }

    private void assertSecurityManager( Object secMgrBean ) {
        if ( secMgrBean == null ) {
            String msg = "There is no " + org.jsecurity.mgt.SecurityManager.class.getName() + " instance bound in in the " +
                    "Spring WebApplicationContext under the name of '" + getSecurityManagerBeanName() + "'."  +
                    "  Please ensure that such a bean exists, or you can change which bean is accessed by " +
                    "setting the " + getClass().getName() + "#SecurityManagerBeanName attribute.";
            throw new IllegalStateException( msg );
        }
    }

    public SecurityManager getSecurityManager() {
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( getServletContext() );
        Object secMgrBean = appCtx.getBean( getSecurityManagerBeanName() );
        assertSecurityManager( secMgrBean );
        return (SecurityManager)secMgrBean;
    }
}
