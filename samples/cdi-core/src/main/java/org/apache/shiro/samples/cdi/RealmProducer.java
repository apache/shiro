package org.apache.shiro.samples.cdi;


import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.util.Initializable;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.Typed;

/**
 *
 */
public class RealmProducer {

    @Produces
    @Typed({Realm.class, Initializable.class})
    private IniRealm createIniRealm(@New IniRealm iniRealm) {
        Ini ini = Ini.fromResourcePath("classpath:shiro.ini");
        iniRealm.setIni(ini);
        return iniRealm;
    }

//    @Produces
//    @ApplicationScoped
//    private Ini loadShiroIni() {
//        return Ini.fromResourcePath("classpath:shiro.ini");
//    }

}
