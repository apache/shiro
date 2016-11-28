package org.apache.shiro.cdi.web;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.TextConfigurationRealm;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

@ApplicationScoped
class StubConfiguration {

//    @Typed({Realm.class, Initializable.class})
    @Produces
    @ApplicationScoped
    private Realm createTestRealm() {
        return new TextConfigurationRealm();
    }
}
