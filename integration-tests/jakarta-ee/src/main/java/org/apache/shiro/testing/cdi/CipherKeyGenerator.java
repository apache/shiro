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
package org.apache.shiro.testing.cdi;

import jakarta.enterprise.context.ApplicationScoped;

import org.apache.shiro.cdi.annotations.CipherKeySupplier;

@ApplicationScoped
public class CipherKeyGenerator implements CipherKeySupplier {
    @Override
    public String get() {
        return "34D7E5C61B87A38C971B3716AED7899E";
    }
}
