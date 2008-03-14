/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
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
