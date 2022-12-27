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
package org.apache.shiro.ee.cdi;

import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.apache.shiro.crypto.cipher.AesCipherService;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.omnifaces.util.Beans;
import org.omnifaces.util.Lazy;
import static org.omnifaces.util.Utils.isBlank;

/**
 * Shiro cipher key generator
 */
public class KeyGen {
    private final Lazy<AesCipherService> cipherService = new Lazy<>(AesCipherService::new);

    public interface CipherKeySupplier extends Supplier<String> {
    }

    public void setSecurityManager(DefaultWebSecurityManager securityManager) {
        var rememberMeManager = securityManager.getRememberMeManager();
        if (rememberMeManager instanceof AbstractRememberMeManager) {
            ((AbstractRememberMeManager) rememberMeManager).setCipherKey(generateCipherKey());
        }
    }

    private byte[] generateCipherKey() {
        var cipherKeySupplier = Beans.getReference(CipherKeySupplier.class);
        if (cipherKeySupplier == null || isBlank(cipherKeySupplier.get())) {
            return cipherService.get().generateNewKey().getEncoded();
        } else {
            return cipherKeySupplier.get().getBytes(StandardCharsets.UTF_8);
        }
    }
}
