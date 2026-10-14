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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import jakarta.servlet.SessionTrackingMode;
import jakarta.servlet.annotation.WebListener;

import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.WebEnvironment;
import org.omnifaces.util.Faces;
import static org.apache.shiro.ee.listeners.IniEnvironment.hasFacesContext;

/**
 * Automatic, adds ability to disable via system property
 * Adds ability to have two shiro.ini configuration files that are merged
 */
@WebListener
public class EnvironmentLoaderListener extends EnvironmentLoader implements ServletContextListener {
    private static final String SHIRO_EE_DISABLED_PARAM = "org.apache.shiro.ee.disabled";
    private static final String SHIRO_EE_REDIRECT_DISABLED_PARAM = "org.apache.shiro.ee.redirect.disabled";
    private static final String SHIRO_EE_ENABLE_URL_SESSION_TRACKING_PARAM = "org.apache.shiro.ee.enable-url-session-tracking";
    private static final String SHIRO_EE_SESSION_TRACKING_CONFIGURATION_DISABLED_PARAM =
            "org.apache.shiro.ee.session-tracking-configuration.disabled";
    private static final String SHIRO_EE_DISABLE_SECURE_SESSION_COOKIE_PARAM =
            "org.apache.shiro.ee.secure-session-cookie.disabled";
    private static final String SHIRO_EE_DISABLE_CHAR_ENCODING_PARAM = "org.apache.shiro.ee.disable-character-encoding";
    private static final String SHIRO_EE_CHAR_ENCODING_PARAM = "org.apache.shiro.ee.character-encoding";
    private static final String FORM_RESUBMIT_DISABLED_PARAM = "org.apache.shiro.form-resubmit.disabled";
    private static final String FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM = "org.apache.shiro.form-resubmit.anonymous.disabled";
    private static final String FORM_RESUBMIT_SECURE_COOKIES = "org.apache.shiro.form-resubmit.secure-cookies";
    private static final String FORM_RESUBMIT_AJAX_RENDER_ALL_DISABLED_PARAM =
            "org.apache.shiro.form-resubmit.ajax-render-all.disabled";
    private static final String SHIRO_WEB_DISABLE_PRINCIPAL_PARAM = "org.apache.shiro.web.disable-principal";

    public static boolean isShiroEEDisabled(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(SHIRO_EE_DISABLED_PARAM));
    }

    public static boolean isShiroEERedirectDisabled(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(SHIRO_EE_REDIRECT_DISABLED_PARAM));
    }

    public static boolean isFormResubmitDisabled(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(FORM_RESUBMIT_DISABLED_PARAM));
    }

    /**
     * @param ctx servlet context
     * @return whether replaying an expired-session form for a subject that is neither authenticated
     * nor remembered, i.e. without a login flow, is disabled
     */
    public static boolean isAnonymousFormResubmitDisabled(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM));
    }

    public static boolean isFormResubmitSecureCookies(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(FORM_RESUBMIT_SECURE_COOKIES));
    }

    /**
     * @param ctx servlet context
     * @return whether an in-place Faces Ajax replay keeps the form's own render targets
     * instead of re-rendering the whole view, which resynchronizes the page with the rebuilt server-side view
     */
    public static boolean isFormResubmitAjaxRenderAllDisabled(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(FORM_RESUBMIT_AJAX_RENDER_ALL_DISABLED_PARAM));
    }

    public static boolean isServletNoPrincipal(ServletContext ctx) {
        return Boolean.TRUE.equals(ctx.getAttribute(SHIRO_WEB_DISABLE_PRINCIPAL_PARAM));
    }

    public static boolean isCharEncodingEnabled(ServletContext ctx) {
        return !Boolean.TRUE.equals(ctx.getAttribute(SHIRO_EE_DISABLE_CHAR_ENCODING_PARAM));
    }

    public static Charset getCharacterEncoding(ServletContext ctx) {
        Charset encoding = (Charset) ctx.getAttribute(SHIRO_EE_CHAR_ENCODING_PARAM);
        return encoding != null ? encoding : StandardCharsets.UTF_8;
    }

    @Override
    @SuppressWarnings({"checkstyle:NPathComplexity", "checkstyle:CyclomaticComplexity"})
    public void contextInitialized(ServletContextEvent sce) {
        copyBooleanInitParameter(sce.getServletContext(), SHIRO_EE_DISABLED_PARAM);
        copyBooleanInitParameter(sce.getServletContext(), SHIRO_EE_REDIRECT_DISABLED_PARAM);
        copyBooleanInitParameter(sce.getServletContext(), FORM_RESUBMIT_DISABLED_PARAM);
        copyBooleanInitParameter(sce.getServletContext(), FORM_RESUBMIT_ANONYMOUS_DISABLED_PARAM);
        String secureCookiesStr = sce.getServletContext().getInitParameter(FORM_RESUBMIT_SECURE_COOKIES);
        if (Optional.ofNullable(System.getProperty(FORM_RESUBMIT_SECURE_COOKIES)).map(Boolean::valueOf)
                        .or(() -> Optional.ofNullable(secureCookiesStr).map(Boolean::valueOf)).orElse(true)) {
            sce.getServletContext().setAttribute(FORM_RESUBMIT_SECURE_COOKIES, Boolean.TRUE);
        } else {
            sce.getServletContext().setAttribute(FORM_RESUBMIT_SECURE_COOKIES, Boolean.FALSE);
        }
        copyBooleanInitParameter(sce.getServletContext(), FORM_RESUBMIT_AJAX_RENDER_ALL_DISABLED_PARAM);
        copyBooleanInitParameter(sce.getServletContext(), SHIRO_WEB_DISABLE_PRINCIPAL_PARAM);
        copyBooleanInitParameter(sce.getServletContext(), SHIRO_EE_DISABLE_CHAR_ENCODING_PARAM);
        if (sce.getServletContext().getInitParameter(SHIRO_EE_CHAR_ENCODING_PARAM) != null) {
            sce.getServletContext().setAttribute(SHIRO_EE_CHAR_ENCODING_PARAM,
                    Charset.forName(sce.getServletContext().getInitParameter(SHIRO_EE_CHAR_ENCODING_PARAM)));
        }
        if (!isShiroEEDisabled(sce.getServletContext())) {
            if (!Boolean.parseBoolean(sce.getServletContext()
                    .getInitParameter(SHIRO_EE_SESSION_TRACKING_CONFIGURATION_DISABLED_PARAM))) {
                modifySessionTrackingConfiguration(sce);
            }

            modifySecureSessionConfiguration(sce);
            initEnvironment(sce.getServletContext());
        }
    }

    /**
     * Exposes an init parameter's {@code true} as an attribute, for the {@code is...()} methods above
     */
    private static void copyBooleanInitParameter(ServletContext ctx, String name) {
        if (Boolean.parseBoolean(ctx.getInitParameter(name))) {
            ctx.setAttribute(name, Boolean.TRUE);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        if (!isShiroEEDisabled(sce.getServletContext())) {
            destroyEnvironment(sce.getServletContext());
        }
    }

    @Override
    protected Class<? extends WebEnvironment> getDefaultWebEnvironmentClass(ServletContext ctx) {
        if (isShiroEEDisabled(ctx)) {
            return super.getDefaultWebEnvironmentClass(ctx);
        } else {
            return IniEnvironment.class;
        }
    }

    private static void modifySessionTrackingConfiguration(ServletContextEvent sce) {
        Set<SessionTrackingMode> effectiveModes = sce.getServletContext().getEffectiveSessionTrackingModes();
        if (Boolean.parseBoolean(sce.getServletContext().getInitParameter(SHIRO_EE_ENABLE_URL_SESSION_TRACKING_PARAM))) {
            effectiveModes.add(SessionTrackingMode.URL);
        } else {
            effectiveModes.remove(SessionTrackingMode.URL);
        }
        sce.getServletContext().setSessionTrackingModes(effectiveModes);
    }

    private void modifySecureSessionConfiguration(ServletContextEvent sce) {
        if (!Boolean.parseBoolean(sce.getServletContext().getInitParameter(SHIRO_EE_DISABLE_SECURE_SESSION_COOKIE_PARAM))
                && !hasFacesContext() || !Faces.isDevelopment()) {
            sce.getServletContext().getSessionCookieConfig().setSecure(true);
        }
    }
}
