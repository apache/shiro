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
package org.apache.shiro.cdi;

import lombok.RequiredArgsConstructor;
import org.apache.shiro.SecurityUtils;
import java.io.Serializable;

/**
 * Injection point for Shiro Principal
 * <p>
 * Since Principal can be any object, this holder object is required
 * for the producer methods to properly work
 *
 * @param <T> principal type
 */
@RequiredArgsConstructor
public class ShiroPrincipal<T> implements Serializable {
    private static final long serialVersionUID = 1L;
    private final Class<T> principalType;

    /**
     * Returns Typed Shiro Principal
     *
     * @see org.apache.shiro.subject.PrincipalCollection#oneByType(Class)
     * @return Shiro Principal, or null if doesn't exist
     */
    public T get() {
        return SecurityUtils.getSubject().getPrincipals().oneByType(principalType);
    }
}
