package org.jsecurity.spring;

import org.jsecurity.SecurityManager;
import org.jsecurity.web.servlet.JSecurityFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Feb 4, 2008 8:26:14 PM
 */
public class SpringJSecurityFilter extends JSecurityFilter {

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
            String msg = "There is no " + SecurityManager.class.getName() + " instance bound in in the " +
                    "Spring WebApplicationContext under the name of '" + getSecurityManagerBeanName() + "'."  +
                    "  Please ensure that such a bean exists, or you can change which bean is accessed by " +
                    "setting the " + getClass().getName() + "#SecurityManagerBeanName attribute.";
            throw new IllegalStateException( msg );
        }
        if ( !(secMgrBean instanceof SecurityManager)) {
            String msg = "The " + getClass().getName() + " class requires the web application's " +
                    "SecurityManager instance to be of type [" + SecurityManager.class.getName() + " ].";
            throw new IllegalStateException( msg );
        }
    }

    protected SecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext( sc );
        Object secMgrBean = appCtx.getBean( getSecurityManagerBeanName() );
        assertWebSecurityManager( secMgrBean );
        return (SecurityManager)secMgrBean;
    }

}
