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
package org.apache.shiro.testing.jakarta.ee;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;

import org.apache.shiro.ee.filters.Forms.FallbackPredicate;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Fallback if we are an auth page
 */
@Named
@ApplicationScoped
public class UseFallback implements FallbackPredicate {
    @Override
    public boolean useFallback(String path, HttpServletRequest request) {
        return path.contains("shiro/auth/");
    }
}
