package org.apache.shiro.cdi.web.producers;

import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cdi.producers.AbstractSecurityManagerProducer;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.Typed;

public class WebSecurityManagerProducer extends AbstractSecurityManagerProducer {


    @Produces
    @ApplicationScoped
    @Typed({DefaultWebSecurityManager.class,
            DefaultSecurityManager.class,
            WebSecurityManager.class,
            SecurityManager.class,
            Destroyable.class})
    @Override
    protected DefaultWebSecurityManager securityManager(@New(DefaultWebSecurityManager.class) DefaultSecurityManager securityManager,
                                                        Instance<Realm> realms,
                                                        EventBus eventBus,
                                                        SessionManager sessionManager,
                                                        Instance<CacheManager> cacheManager,
                                                        SubjectDAO subjectDAO,
                                                        SubjectFactory subjectFactory,
                                                        Instance<RememberMeManager> rememberMeManager,
                                                        AuthenticationStrategy authenticationStrategy,
                                                        Instance<PermissionResolver> permissionResolver,
                                                        Instance<RolePermissionResolver> rolePermissionResolver) {

        return configureSecurityManager((DefaultWebSecurityManager) securityManager,
                                        realms,
                                        eventBus,
                                        sessionManager,
                                        cacheManager,
                                        subjectDAO,
                                        subjectFactory,
                                        rememberMeManager,
                                        authenticationStrategy,
                                        permissionResolver,
                                        rolePermissionResolver);
    }

    @Produces
    protected DefaultWebSubjectFactory webSubjectFactory(@New DefaultWebSubjectFactory subjectFactory) {
        return subjectFactory;
    }

    @Produces
    protected RememberMeManager rememberMeManager(@New CookieRememberMeManager rememberMeManager) {
//        rememberMeManager.setCookie(rememberMeCookieTemplate());
        return rememberMeManager;
    }

    @Produces
    @ApplicationScoped
    protected FilterChainResolver filterChainResolver(@New PathMatchingFilterChainResolver filterChainResolver) {
        return filterChainResolver;
    }
}
