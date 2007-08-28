package org.jsecurity.spring.servlet;

import org.jsecurity.web.servlet.SecurityContextFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class SpringSecurityContextFilter extends SecurityContextFilter {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";

    protected String securityManagerBeanName = "securityManager";

    public String getSecurityManagerBeanName() {
        return securityManagerBeanName;
    }

    public void setSecurityManagerBeanName( String securityManagerBeanName ) {
        this.securityManagerBeanName = securityManagerBeanName;
    }

    public void init() throws Exception {
        String beanName = getFilterConfig().getInitParameter( SECURITY_MANAGER_BEAN_NAME_PARAM_NAME );
        if ( beanName != null ) {
            setSecurityManagerBeanName( beanName );
        }
        super.init();
    }

    protected org.jsecurity.SecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( sc );
        return (org.jsecurity.SecurityManager)appCtx.getBean( getSecurityManagerBeanName() );
    }
}
