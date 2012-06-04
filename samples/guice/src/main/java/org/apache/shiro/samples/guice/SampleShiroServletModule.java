package org.apache.shiro.samples.guice;

import com.google.inject.Provides;
import com.google.inject.name.Names;
import org.apache.shiro.config.Ini;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.realm.text.IniRealm;

import javax.inject.Singleton;
import javax.servlet.ServletContext;
import java.net.MalformedURLException;
import java.net.URL;

public class SampleShiroServletModule extends ShiroWebModule {
    private final ServletContext servletContext;

    public SampleShiroServletModule(ServletContext servletContext) {
        super(servletContext);

        this.servletContext = servletContext;
    }

    @Override
    protected void configureShiroWeb() {
        bindConstant().annotatedWith(Names.named("shiro.loginUrl")).to("/login.jsp");
        try {
            this.bindRealm().toConstructor(IniRealm.class.getConstructor(Ini.class));
        } catch (NoSuchMethodException e) {
            addError("Could not locate proper constructor for IniRealm.", e);
        }

        this.addFilterChain("/login.jsp", AUTHC);
        this.addFilterChain("/logout", LOGOUT);
        this.addFilterChain("/account/**", AUTHC);
        this.addFilterChain("/remoting/**", AUTHC, config(ROLES, "b2bClient"), config(PERMS, "remote:invoke:lan,wan"));
    }

    @Provides
    @Singleton
    Ini loadShiroIni() throws MalformedURLException {
        URL iniUrl = servletContext.getResource("/WEB-INF/shiro.ini");
        return Ini.fromResourcePath("url:" + iniUrl.toExternalForm());
    }
}
