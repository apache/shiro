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
package org.apache.shiro.ee.util;

import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * transforms Java to Jakarta namespace
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings("HideUtilityClassConstructor")
public class JakartaTransformer {
    @Getter
    @SuppressWarnings("ConstantName")
    private static final boolean jakarta = HttpServletRequest.class.getPackageName().startsWith("jakarta");
    private static final Pattern REPLACE_JAVA_WITH_JAKARTA_PATTERN = Pattern.compile("javax\\.(\\w+)\\.");

    public static String jakartify(String className) {
        return REPLACE_JAVA_WITH_JAKARTA_PATTERN.matcher(className).replaceAll(
                isJakarta() ? "jakarta.$1." : "javax.$1.");
    }
}
