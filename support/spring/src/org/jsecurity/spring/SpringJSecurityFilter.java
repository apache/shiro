package org.jsecurity.spring;

import org.jsecurity.SecurityManager;
import org.jsecurity.web.servlet.JSecurityFilter;
import org.springframework.beans.factory.BeanNotOfRequiredTypeException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;

/**
 * Relies on Spring to define and initialize the JSecurity SecurityManager instance (and all of its dependencies)
 * and makes it avaialble to this filter by performing a Spring bean lookup.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SpringJSecurityFilter extends JSecurityFilter {

    public static final String SECURITY_MANAGER_BEAN_NAME_PARAM_NAME = "securityManagerBeanName";
    public static final String DEFAULT_SECURITY_MANAGER_BEAN_NAME = "securityManager";

    protected String securityManagerBeanName = DEFAULT_SECURITY_MANAGER_BEAN_NAME;

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
        if (!appCtx.containsBean(beanName)) {
            String msg = "There is no " + SecurityManager.class.getName() + " instance available in in the " +
                "Spring WebApplicationContext under the bean name of '" + getSecurityManagerBeanName() +
                "'.  Please ensure that such a bean exists, or you can change which bean is retrieved by " +
                "setting this filter's 'securityManagerBeanName' init-param.";
            throw new ApplicationContextException(msg);
        }
        Object retrieved = appCtx.getBean(beanName);
        if (!(retrieved instanceof SecurityManager)) {
            throw new BeanNotOfRequiredTypeException(beanName, SecurityManager.class, retrieved.getClass());
        }
        return (SecurityManager) retrieved;
    }

    protected SecurityManager getSecurityManager() {
        ServletContext sc = getFilterConfig().getServletContext();
        ApplicationContext appCtx = WebApplicationContextUtils.getRequiredWebApplicationContext(sc);
        return getSecurityManager( appCtx );
    }

}
