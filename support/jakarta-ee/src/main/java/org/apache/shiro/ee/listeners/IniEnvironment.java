/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.listeners;

import java.nio.charset.StandardCharsets;
import org.apache.shiro.ee.filters.FormAuthenticationFilter;
import org.apache.shiro.ee.filters.LogoutFilter;
import org.apache.shiro.ee.filters.SslFilter;
import java.util.Map;
import javax.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.cdi.annotations.CipherKeySupplier;
import org.apache.shiro.config.Ini;
import org.apache.shiro.crypto.cipher.AesCipherService;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.omnifaces.util.Beans;
import org.omnifaces.util.Lazy;
import static org.omnifaces.util.Utils.isBlank;

/**
 * Ability to merge two configuration files, exactly two
 */
@Slf4j
public class IniEnvironment extends IniWebEnvironment {
    private String otherConfigLocation;

    @SuppressWarnings("deprecation")
    private static final class SecurityManagerFactory extends WebIniSecurityManagerFactory {
        private final Lazy<AesCipherService> cipherService = new Lazy<>(AesCipherService::new);

        @Override
        protected Map<String, ?> createDefaults(Ini ini, Ini.Section mainSection) {
            @SuppressWarnings("unchecked")
            Map<String, Filter> defaults = (Map<String, Filter>) super.createDefaults(ini, mainSection);
            try {
                // SSL filter must be first because it will trigger an exception if OmniFaces is not available
                var sslFilter = new SslFilter();
                defaults.replace(DefaultFilter.authc.name(), new FormAuthenticationFilter());
                defaults.replace(DefaultFilter.ssl.name(), sslFilter);
                defaults.replace(DefaultFilter.logout.name(), new LogoutFilter());
            } catch (Throwable e) {
                log.warn("unable to initialize filters", e);
            }
            return defaults;
        }

        @Override
        protected SecurityManager createDefaultInstance() {
            return new DefaultWebSecurityManager(this::generateCipherKey);
        }

        private byte[] generateCipherKey() {
            var cipherKeySupplier = Beans.getManager() == null ? null
                    : Beans.getReference(CipherKeySupplier.class);
            if (cipherKeySupplier == null || isBlank(cipherKeySupplier.get())) {
                return cipherService.get().generateNewKey().getEncoded();
            } else {
                return cipherKeySupplier.get().getBytes(StandardCharsets.UTF_8);
            }
        }
    }

    public IniEnvironment() {
        var securityManagerFactory = new SecurityManagerFactory();
        securityManagerFactory.getReflectionBuilder().setAlternateObjectSupplier(Beans::getInstance);
        setSecurityManagerFactory(securityManagerFactory);
    }

    @Override
    public void setConfigLocations(String[] configLocations) {
        if (configLocations.length == 2) {
            otherConfigLocation = configLocations[1];
            super.setConfigLocations(configLocations[0]);
        } else {
            super.setConfigLocations(configLocations);
        }
    }

    @Override
    protected Ini getFrameworkIni() {
        if (otherConfigLocation != null) {
            return createIni(otherConfigLocation, true);
        } else {
            return super.getFrameworkIni();
        }
    }
}
