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

    public WebSecurityManager getSecurityManager() {
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( getServletContext() );
        Object secMgrBean = appCtx.getBean( getSecurityManagerBeanName() );
        assertWebSecurityManager( secMgrBean );
        return (WebSecurityManager)secMgrBean;
    }
}
