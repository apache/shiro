package org.apache.shiro.cdi.core.producers;

import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cdi.producers.AbstractSecurityManagerProducer;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionFactory;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.util.Destroyable;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.Typed;

public class SecurityManagerProducer extends AbstractSecurityManagerProducer {

    @Produces
    @ApplicationScoped
    @Typed({SecurityManager.class, DefaultSecurityManager.class, Destroyable.class})
    @Override
    protected DefaultSecurityManager securityManager(@New DefaultSecurityManager securityManager,
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

        return configureSecurityManager(securityManager,
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
    protected DefaultSubjectFactory subjectFactory(@New DefaultSubjectFactory subjectFactory) {
        return subjectFactory;
    }

    @Produces
    protected SessionManager sessionManager(@New DefaultSessionManager sessionManager,
                                            SessionDAO sessionDAO,
                                            SessionFactory sessionFactory) {

        sessionManager.setSessionDAO(sessionDAO);
        sessionManager.setSessionFactory(sessionFactory);
        sessionManager.setDeleteInvalidSessions(true); // TODO: add configuration for this.
        return sessionManager;
    }

    @Produces
    protected MemorySessionDAO sessionDAO(@New MemorySessionDAO memorySessionDAO) {
        return memorySessionDAO;
    }


}
