/*
 * Copyright (C) 2005-2007 Les Hazlewood
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

import org.jsecurity.web.servlet.SecurityContextFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;

/**
 * <p>Extension of the {@link SecurityContextFilter} that retrieves the {@link SecurityManager} for the current request
 * from a Spring application context and ensures that the {@link SecurityManager} is available throughout the
 * request.</p>
 *
 * <p>In Spring MVC environments, the {@link org.jsecurity.spring.servlet.security.SecurityContextInterceptor} may
 * be used instead of this filter.  This class offers a Servlet filter based alternative to using Spring interceptors.
 * It is useful in Spring enviroments that do not use Spring MVC.</p>
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SpringSecurityContextFilter extends SecurityContextFilter {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";
    public static final String DEFAULT_SECURITY_MANAGER_BEAN_NAME = "securityManager";

    protected String securityManagerBeanName = DEFAULT_SECURITY_MANAGER_BEAN_NAME;

    public String getSecurityManagerBeanName() {
        return securityManagerBeanName;
    }

    public void setSecurityManagerBeanName( String securityManagerBeanName ) {
        this.securityManagerBeanName = securityManagerBeanName;
    }

    public void init() throws Exception {
        String beanName = getFilterConfig().getInitParameter( SECURITY_MANAGER_BEAN_NAME_PARAM_NAME );
        if ( beanName != null ) {
            setSecurityManagerBeanName( beanName.trim() );
        }
        super.init();
    }

    protected org.jsecurity.SecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( sc );
        return (org.jsecurity.SecurityManager)appCtx.getBean( getSecurityManagerBeanName() );
    }
}
