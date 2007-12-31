package org.jsecurity.spring.servlet;

import org.jsecurity.web.WebSecurityManager;
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

    public WebSecurityManager getSecurityManager() {
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( getServletContext() );
        return (WebSecurityManager)appCtx.getBean( getSecurityManagerBeanName() );
    }
}
