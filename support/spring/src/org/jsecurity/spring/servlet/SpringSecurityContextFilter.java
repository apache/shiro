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

import org.jsecurity.SecurityManager;
import org.jsecurity.web.WebSecurityManager;
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
 * @deprecated in Spring environments, configure the {@link SpringSecurityManagerListener} instead, and then define the
 * standard {@link SecurityContextFilter SecurityContextFilter}.  This class will be removed before the next final
 * release.
 *
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

    public void onFilterConfigSet() throws Exception {
        String beanName = getFilterConfig().getInitParameter( SECURITY_MANAGER_BEAN_NAME_PARAM_NAME );
        if ( beanName != null ) {
            setSecurityManagerBeanName( beanName );
        }
        super.onFilterConfigSet();
    }

    private void assertWebSecurityManager( Object secMgrBean ) {
        if ( secMgrBean == null ) {
            String msg = "There is no " + WebSecurityManager.class.getName() + " instance bound in in the " +
                    "Spring WebApplicationContext under the name of '" + getSecurityManagerBeanName() + "'."  +
                    "  Please ensure that such a bean exists, or you can change which bean is accessed by " +
                    "setting the " + getClass().getName() + "#SecurityManagerBeanName attribute.";
            throw new IllegalStateException( msg );
        }
        if ( !(secMgrBean instanceof WebSecurityManager)) {
            String msg = "The " + getClass().getName() + " class requires the web application's " +
                    "SecurityManager instance to be of type [" + WebSecurityManager.class.getName() + " ].";
            throw new IllegalStateException( msg );
        }
    }

    protected WebSecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( sc );
        Object secMgrBean = appCtx.getBean( getSecurityManagerBeanName() );
        assertWebSecurityManager( secMgrBean );
        return (WebSecurityManager)secMgrBean;
    }
}
