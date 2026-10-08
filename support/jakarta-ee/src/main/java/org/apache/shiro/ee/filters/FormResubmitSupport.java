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
package org.apache.shiro.ee.filters;

import static jakarta.faces.application.StateManager.STATE_SAVING_METHOD_CLIENT;
import static jakarta.faces.application.StateManager.STATE_SAVING_METHOD_PARAM_NAME;
import static org.apache.shiro.SecurityUtils.getSecurityManager;
import static org.apache.shiro.SecurityUtils.isSecurityManagerTypeOf;
import static org.apache.shiro.SecurityUtils.unwrapSecurityManager;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_URL_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.LOCATION;
import static jakarta.servlet.http.HttpServletResponse.SC_FOUND;
import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.addCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.deleteCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.getCookieAge;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitDisabled;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import static org.apache.shiro.ee.listeners.IniEnvironment.hasFacesContext;
import static org.apache.shiro.web.filter.authz.PortFilter.DEFAULT_HTTP_PORT;
import static org.apache.shiro.web.filter.authz.PortFilter.HTTP_SCHEME;
import static org.apache.shiro.web.filter.authz.SslFilter.DEFAULT_HTTPS_PORT;
import static org.apache.shiro.web.filter.authz.SslFilter.HTTPS_SCHEME;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import jakarta.faces.context.FacesContext;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.mgt.AbstractRememberMeManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.util.WebUtils;
import org.jsoup.Jsoup;
import org.jsoup.select.Elements;
import org.omnifaces.util.Faces;
import org.omnifaces.util.ResourcePaths;
import org.omnifaces.util.Servlets;
import org.omnifaces.util.Utils;

/**
 * supporting methods for {@link Forms}
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings({"checkstyle:HideUtilityClassConstructor", "checkstyle:MethodCount"})
public class FormResubmitSupport {
    static final String SHIRO_FORM_DATA_KEY = "org.apache.shiro.form-data-key";
    static final String SESSION_EXPIRED_PARAMETER = "org.apache.shiro.sessionExpired";
    static final String FORM_IS_RESUBMITTED = "org.apache.shiro.form-is-resubmitted";
    static final String FORM_DATA_CACHE = "org.apache.shiro.form-data-cache";
    // encoded view state
    private static final String FACES_VIEW_STATE = "jakarta.faces.ViewState";
    private static final Pattern STATEFUL_VIEW_STATE_PATTERN = Pattern.compile("-?\\d+:-?\\d+");
    private static final String FACES_SOURCE = "jakarta.faces.source";
    private static final String FACES_PARTIAL_PREFIX = "jakarta.faces.partial.";
    private static final String FACES_BEHAVIOR_PREFIX = "jakarta.faces.behavior.";
    private static final String SEC_FETCH_SITE = "Sec-Fetch-Site";
    private static final String ORIGIN = "Origin";

    static class HttpMethod {
        static final String GET = "GET";
        static final String POST = "POST";
    }

    static class HttpHeaderConstants {
        static final String LOCATION = "Location";
    }

    /**
     * Form fields prepared for replay
     *
     * @param result decoded form fields, by name
     * @param isPartialAjaxRequest whether the saved form was submitted via Faces Ajax
     * @param isStatelessRequest whether the saved form carries no server-side view state
     */
    record PartialAjaxResult(Map<String, List<String>> result, boolean isPartialAjaxRequest,
                             boolean isStatelessRequest) { }

    static void savePostDataForResubmit(HttpServletRequest request, HttpServletResponse response, @NonNull String loginUrl) {
        if (isPostRequest(request) && isSecurityManagerTypeOf(getSecurityManager(),
                DefaultSecurityManager.class) && shouldSavePostData(request)) {
            String postData = getPostData(request);
            var cacheKey = UUID.randomUUID();
            DefaultSecurityManager dsm = getSecurityManager(DefaultSecurityManager.class);
            if (dsm.getCacheManager() != null) {
                var cache = dsm.getCacheManager().getCache(FORM_DATA_CACHE);
                var rememberMeManager = getRememberMeManager();
                if (rememberMeManager != null && rememberMeManager.getCipherService() != null) {
                    cache.put(cacheKey, rememberMeManager.getCipherService()
                            .encrypt(postData.getBytes(StandardCharsets.UTF_8),
                                    rememberMeManager.getEncryptionCipherKey()).getBytes());
                } else {
                    log.warn("Post-data was saved in plain text due to rememberMeManager not being available");
                    cache.put(cacheKey, postData);
                }
                addCookie(response, request.getServletContext(), SHIRO_FORM_DATA_KEY,
                        cacheKey.toString(), getCookieAge(request, dsm), true);
            } else {
                log.warn("Shiro Cache manager is not configured, cannot store form data");
            }
        }
        boolean isFacesGetRequest = HttpMethod.GET.equalsIgnoreCase(request.getMethod());
        doFacesRedirect(request, response, request.getContextPath() + loginUrl
                + (isFacesGetRequest ? "" : "?%s=true"), SESSION_EXPIRED_PARAMETER);
    }

    static boolean isPostRequest(ServletRequest request) {
        return request instanceof HttpServletRequest
                && HttpMethod.POST.equalsIgnoreCase(WebUtils.toHttp(request).getMethod());
    }

    @SneakyThrows(IOException.class)
    static String getPostData(ServletRequest request) {
        return request.getReader().lines().collect(Collectors.joining());
    }

    static String getSavedFormDataFromKey(@NonNull UUID savedFormDataKey, Consumer<Cache<Object, ?>> cacheConsumer) {
        String savedFormData = null;
        if (isSecurityManagerTypeOf(getSecurityManager(), DefaultSecurityManager.class)) {
            DefaultSecurityManager dsm = getSecurityManager(DefaultSecurityManager.class);
            if (dsm.getCacheManager() != null) {
                var cache = dsm.getCacheManager().getCache(FORM_DATA_CACHE);
                var rememberMeManager = getRememberMeManager();
                if (rememberMeManager != null && rememberMeManager.getCipherService() != null) {
                    var cachedData = Optional.ofNullable((byte[]) cache.get(savedFormDataKey));
                    savedFormData = cachedData.map(encryptedData ->
                            decrypt(encryptedData, rememberMeManager)).orElse(null);
                } else {
                    savedFormData = (String) cache.get(savedFormDataKey);
                }
                cacheConsumer.accept(cache);
            }
        }
        return savedFormData;
    }

    static String decrypt(byte[] encrypted, AbstractRememberMeManager rememberMeManager) {
        try {
            Objects.requireNonNull(rememberMeManager, "rememberMeManager cannot be null.");
            return new String(rememberMeManager.getCipherService()
                    .decrypt(encrypted, rememberMeManager.getDecryptionCipherKey()).getClonedBytes(),
                    StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            log.debug("Failed to decrypt", e);
            return null;
        }
    }

    static String decrypt(String encrypted, AbstractRememberMeManager rememberMeManager) {
        if (encrypted == null) {
            return null;
        }
        try {
            return decrypt(Base64.decode(encrypted), rememberMeManager);
        } catch (IllegalArgumentException e) {
            log.debug("Failed to decode", e);
            return null;
        }
    }

    static void saveRequest(HttpServletRequest request, HttpServletResponse response, boolean useReferer) {
        String path = useReferer ? getReferer(request)
                : Servlets.getRequestURIWithQueryString(request);
        var rememberMeManager = getRememberMeManager();
        if (path != null && rememberMeManager != null) {
            Servlets.addResponseCookie(request, response, WebUtils.SAVED_REQUEST_KEY,
                    rememberMeManager.getCipherService().encrypt(path.getBytes(StandardCharsets.UTF_8),
                            rememberMeManager.getEncryptionCipherKey()).toBase64(),
                    null, request.getContextPath(),
                    // cookie age = session timeout
                    getCookieAge(request, getSecurityManager()));
        }
    }

    static void saveRequestReferer(boolean rv, HttpServletRequest request, HttpServletResponse response) {
        if (rv && HttpMethod.GET.equalsIgnoreCase(request.getMethod())) {
            if (Servlets.getRequestCookie(request, WebUtils.SAVED_REQUEST_KEY) == null) {
                // only save refer when there is no saved request cookie already,
                // and only as a last resort
                saveRequest(request, response, true);
            }
        }
    }

    static String getReferer(HttpServletRequest request) {
        return normalizeSavedRequest(request.getHeader("referer"), request);
    }

    static String normalizeSavedRequest(String savedRequest, HttpServletRequest request) {
        if (savedRequest == null || savedRequest.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(savedRequest);
            String rawPath = uri.getRawPath();
            if (rawPath == null || !rawPath.startsWith("/")) {
                // opaque URI (mailto:, javascript:), or relative / empty path
                return null;
            }
            String path = uri.getPath();
            if (!path.equals(WebUtils.normalize(path))) {
                // reject anything non-canonical: "//", "/./", "/../", and traversal
                // above root (normalize returns null there, so equals() is false)
                return null;
            }
            String contextPath = WebUtils.getContextPath(request);
            if (!contextPath.isEmpty()
                    && !path.equals(contextPath)
                    && !path.startsWith(contextPath + "/")) {
                return null;
            }
            return Utils.formatURLWithQueryString(rawPath, uri.getRawQuery());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Redirects the user to saved request after login, if available
     * Resubmits the form that caused the logout upon successful login.Form resubmission supports JSF and Ajax forms
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param useFallbackPath predicate whether to use fall back path
     * @param fallbackPath the fallback path to use if no saved request is found
     * @param resubmit if true, attempt to resubmit the form that was unsubmitted prior to logout
     */
    static void redirectToSaved(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath, boolean resubmit) {
        String savedRequest = normalizeSavedRequest(decrypt(Servlets.getRequestCookie(request, WebUtils.SAVED_REQUEST_KEY),
                getRememberMeManager()), request);
        if (savedRequest != null) {
            doRedirectToSaved(request, response, savedRequest, resubmit);
        } else {
            redirectToView(request, response, useFallbackPath, fallbackPath);
        }
    }

    /**
     * redirect to saved request, possibly resubmitting an existing form
     * the saved request is via a cookie
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param useFallbackPath predicate whether to use fall back path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    static void redirectToSaved(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath) {
        redirectToSaved(request, response, useFallbackPath, fallbackPath,
                !isFormResubmitDisabled(request.getServletContext()));
    }


    private static void doRedirectToSaved(HttpServletRequest request, HttpServletResponse response,
            @NonNull String savedRequest, boolean resubmit) {
        deleteCookie(response, request.getServletContext(), WebUtils.SAVED_REQUEST_KEY);
        String savedFormDataKeyString = Servlets.getRequestCookie(request, SHIRO_FORM_DATA_KEY);
        boolean doRedirectAtEnd = true;
        if (savedFormDataKeyString != null && resubmit) {
            AtomicReference<Cache<Object, ?>> cache = new AtomicReference<>();
            UUID savedFormDataKey = UUID.fromString(savedFormDataKeyString);
            String formData = getSavedFormDataFromKey(savedFormDataKey, cache::set);
            try {
                if (formData != null) {
                    resubmitSavedForm(formData, savedRequest, request, response, false, true);
                    doRedirectAtEnd = false;
                } else {
                    deleteCookie(response, request.getServletContext(), SHIRO_FORM_DATA_KEY);
                }
            } finally {
                if (cache.get() != null) {
                    cache.get().remove(savedFormDataKey);
                }
            }
        }
        if (doRedirectAtEnd) {
            doFacesRedirect(request, response, savedRequest);
        }
    }

    /**
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     */
    static void redirectToView(HttpServletRequest request, HttpServletResponse response) {
        redirectToView(request, response, (path, req) -> false, null);
    }

    /**
     * redirects to current view after a form submit,
     * or the fallback path if predicate succeeds
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param useFallbackPath predicate whether to use fall back path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    @SneakyThrows
    static void redirectToView(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath) {
        boolean useFallback = useFallbackPath.useFallback(request.getRequestURI(), request);
        String referer = getReferer(request);
        String redirectPath = Servlets.getRequestURLWithQueryString(request);
        if (useFallback && referer != null && !isLoginUrl(request)) {
            // the following is used in the logout flow only,
            // because login flow saves the request automatically, without
            // needing a referrer
            useFallback = useFallbackPath.useFallback(referer, request);
            redirectPath = referer;
        }
        if (useFallback) {
            doFacesRedirect(request, response, request.getContextPath() + fallbackPath);
        } else {
            doFacesRedirect(request, response, redirectPath);
        }
    }

    /**
     * flash cookie is preserved here
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param path the path to redirect to
     * @param paramValues the parameters to include in the redirect
     */
    private static void doFacesRedirect(HttpServletRequest request, HttpServletResponse response,
            String path, Object... paramValues) {
        if (hasFacesContext()) {
            Faces.redirect(path, paramValues);
        } else {
            Servlets.facesRedirect(request, response, path, paramValues);
        }
    }

    static boolean isLoginUrl(HttpServletRequest request) {
        String loginUrl = (String) request.getAttribute(LOGIN_URL_ATTR_NAME);
        return loginUrl != null && request.getRequestURI().equals(request.getContextPath() + loginUrl);
    }

    /**
     * Replays a saved form in-process, via a request dispatcher forward, and writes the outcome to the response.
     * Any replay fault is treated as optional and quietly falls back to a plain redirect to the saved request.
     *
     * @param savedRequest already validated by {@link #normalizeSavedRequest}
     */
    static void resubmitSavedForm(@NonNull String savedFormData, @NonNull String savedRequest,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse,
            boolean rememberedAjaxResubmit, boolean redirect) {
        if (!replaySavedForm(savedFormData, savedRequest, originalRequest, originalResponse,
                rememberedAjaxResubmit, redirect)) {
            doFacesRedirect(originalRequest, originalResponse, savedRequest);
        }
    }

    /**
     * @return whether the response has been fully written
     */
    private static boolean replaySavedForm(String savedFormData, String savedRequest,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse,
            boolean rememberedAjaxResubmit, boolean redirect) {
        if (FormResubmitRequest.isResubmit(originalRequest)) {
            log.debug("Recursive form resubmission, skipping replay");
            return false;
        }
        String dispatchPath = getDispatchPath(savedRequest, originalRequest);
        var servletContext = originalRequest.getServletContext();
        if (dispatchPath == null || servletContext.getRequestDispatcher(dispatchPath) == null) {
            log.debug("Form resubmit: rejecting dispatch path for {}", savedRequest);
            return false;
        }
        // These must be written before the replayed response is committed by processResubmitResponse()
        deleteCookie(originalResponse, servletContext, SHIRO_FORM_DATA_KEY);
        Servlets.setNoCacheHeaders(originalRequest, originalResponse);
        try {
            var savedFormFields = parseFormData(savedFormData, getFormCharset(originalRequest, servletContext));
            PartialAjaxResult formData = prepareFormData(savedFormFields, dispatchPath, originalRequest,
                    originalResponse, servletContext);
            var response = new FormResubmitResponse(originalResponse);
            forward(dispatchPath, originalRequest, response, HttpMethod.POST, formData.result);
            boolean needsAjaxRedirectReplay = rememberedAjaxResubmit && !formData.isStatelessRequest;
            var redirectResponse = replayAjaxRequestForRedirect(needsAjaxRedirectReplay, response, dispatchPath,
                    originalRequest, originalResponse, savedFormFields);
            var result = Objects.requireNonNullElse(redirectResponse, response);
            if (isFailed(result.getStatus())) {
                log.debug("Form resubmit to {} failed with status {}", dispatchPath, result.getStatus());
                return false;
            }
            processResubmitResponse(response, redirectResponse, originalRequest, originalResponse, savedRequest,
                    formData.isPartialAjaxRequest, rememberedAjaxResubmit, redirect);
        } catch (ServletException | IOException | RuntimeException e) {
            log.warn("Unable to resubmit form to {}", dispatchPath, e);
            return false;
        }
        if (hasFacesContext()) {
            Faces.responseComplete();
        }
        return true;
    }

    /**
     * The browser's Faces Ajax client awaits a partial response, which the full-page replay above can't provide.
     * The original Ajax request is therefore replayed unmodified, with its now-stale view state,
     * so the application's Ajax view-expired handling supplies the redirect that the client follows
     * to see the replay's outcome. Only this response's status and redirect are used;
     * its flash cookie must not replace the successful POST's messages.
     *
     * @return the captured Ajax response, failed if the application doesn't handle the expired view,
     * or null for a stateless or non-Ajax replay
     */
    private static FormResubmitResponse replayAjaxRequestForRedirect(boolean needsAjaxRedirectReplay,
            FormResubmitResponse response, String dispatchPath, HttpServletRequest originalRequest,
            HttpServletResponse originalResponse, Map<String, List<String>> savedFormFields) {
        if (!needsAjaxRedirectReplay || isFailed(response.getStatus())) {
            return null;
        }
        var redirectResponse = new FormResubmitResponse(originalResponse);
        try {
            forward(dispatchPath, originalRequest, redirectResponse, HttpMethod.POST, savedFormFields);
        } catch (ServletException | IOException | RuntimeException e) {
            // expected without an application view-expired handler
            log.debug("Ajax redirect replay to {} failed", dispatchPath, e);
            redirectResponse.setStatus(SC_INTERNAL_SERVER_ERROR);
        }
        return redirectResponse;
    }

    private static boolean isFailed(int status) {
        return status != SC_OK && status != SC_FOUND;
    }

    /**
     * Derives the dispatcher path from a saved request that is already verified to be within the context path.
     * The container's dispatcher strips path parameters, decodes and normalizes the path before resolving it,
     * which could otherwise reach the WEB-INF and META-INF directories that are inaccessible to browsers.
     * Hence, the same is mirrored here, and the resulting path is checked.
     *
     * @return path and query to dispatch to, or null if rejected
     */
    static String getDispatchPath(@NonNull String savedRequest, HttpServletRequest request) {
        URI uri = URI.create(savedRequest);
        String path = ResourcePaths.addLeadingSlashIfNecessary(
                uri.getRawPath().substring(request.getContextPath().length()).replaceAll(";[^/]*", ""));
        // trailing slash makes a trailing "." or ".." segment resolvable, and matches directories exactly
        String resolvedPath = WebUtils.normalize(ResourcePaths.addTrailingSlashIfNecessary(
                Utils.decodeURL(path).replace('\\', '/')));
        if (resolvedPath == null
                || Utils.startsWithOneOf(resolvedPath.toUpperCase(Locale.ROOT), "/WEB-INF/", "/META-INF/")) {
            return null;
        }
        return Utils.formatURLWithQueryString(path, uri.getRawQuery());
    }

    /**
     * @param path dispatch path already verified by {@link #replaySavedForm} to resolve to a dispatcher
     */
    private static void forward(String path, HttpServletRequest originalRequest, HttpServletResponse response,
            String method, Map<String, List<String>> formFields) throws ServletException, IOException {
        var request = new FormResubmitRequest(originalRequest, method, formFields);
        // FacesServlet creates/releases its own context. Restore a calling Faces login action's afterward.
        FacesContext context = hasFacesContext() ? Faces.getContext() : null;
        try {
            if (context != null) {
                Faces.setContext(null);
            }
            originalRequest.getServletContext().getRequestDispatcher(path).forward(request, response);
        } finally {
            if (context != null) {
                Faces.setContext(context);
            }
        }
    }

    /**
     * Parses {@code application/x-www-form-urlencoded} data into decoded fields, by name.
     * Unlike {@link Servlets#toParameterMap(String)}, empty values are preserved,
     * since Faces treats an empty field differently from an absent one.
     */
    static Map<String, List<String>> parseFormData(@NonNull String formData, @NonNull Charset charset) {
        var formFields = new LinkedHashMap<String, List<String>>();
        for (String field : formData.split("&")) {
            if (!field.isEmpty()) {
                String[] pair = field.split("=", 2);
                formFields.computeIfAbsent(URLDecoder.decode(pair[0], charset), name -> new ArrayList<>())
                        .add(pair.length == 2 ? URLDecoder.decode(pair[1], charset) : "");
            }
        }
        return formFields;
    }

    /**
     * @return the encoding the container would have used for the saved form's parameters
     */
    static Charset getFormCharset(HttpServletRequest request, ServletContext servletContext) {
        return Optional.ofNullable(request.getCharacterEncoding())
                .or(() -> Optional.ofNullable(servletContext.getRequestCharacterEncoding()))
                .map(encoding -> {
                    try {
                        return Charset.forName(encoding);
                    } catch (IllegalArgumentException e) {
                        log.debug("Ignoring unsupported request encoding {}", encoding, e);
                        return null;
                    }
                }).orElse(StandardCharsets.UTF_8);
    }

    private static PartialAjaxResult prepareFormData(Map<String, List<String>> savedFormFields, String path,
            HttpServletRequest request, HttpServletResponse response, ServletContext servletContext)
            throws IOException, ServletException {
        boolean isStateless = isJSFClientStateSavingMethod(servletContext) || !isJSFStatefulForm(savedFormFields);
        var formFields = new LinkedHashMap<>(savedFormFields);
        if (!isStateless) {
            refreshJSFViewState(path, request, response, formFields);
        }
        return noJSFAjaxRequests(formFields, isStateless);
    }

    /**
     * Only a successful replay reaches the browser: the successful POST's headers and cookies,
     * then the Ajax redirect replay's headers without its cookies, so that its flash cookie
     * doesn't replace the submitted-form messages.
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    private static void processResubmitResponse(FormResubmitResponse response, FormResubmitResponse redirectResponse,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse, String savedRequest,
            boolean isPartialAjaxRequest, boolean rememberedAjaxResubmit, boolean redirect) throws IOException {
        var result = Objects.requireNonNullElse(redirectResponse, response);
        int status = result.getStatus();
        boolean redirectAsOk = rememberedAjaxResubmit && status == SC_FOUND;
        if (redirectAsOk) {
            // a 200 must not carry the replay's redirect target
            response.removeHeader(LOCATION);
            result.removeHeader(LOCATION);
        }
        response.applyTo(originalResponse, true);
        if (redirectResponse != null) {
            redirectResponse.applyTo(originalResponse, false);
        }
        originalResponse.setStatus(redirectAsOk ? SC_OK : status);
        if (isPartialAjaxRequest && (status == SC_FOUND || redirect)) {
            doFacesRedirect(originalRequest, originalResponse, savedRequest);
        } else {
            originalResponse.getOutputStream().write(result.getBuffer());
        }
    }

    public static DefaultWebSessionManager getNativeSessionManager(SecurityManager securityManager) {
        DefaultWebSessionManager rv = null;
        SecurityManager unwrapped = unwrapSecurityManager(securityManager, SecurityManager.class, type -> false);
        if (unwrapped instanceof SessionsSecurityManager ssm) {
            var sm = ssm.getSessionManager();
            if (sm instanceof DefaultWebSessionManager manager) {
                rv = manager;
            }
        }
        return rv;
    }

    static AbstractRememberMeManager getRememberMeManager() {
        if (isSecurityManagerTypeOf(getSecurityManager(), DefaultSecurityManager.class)) {
            var dsm = getSecurityManager(DefaultSecurityManager.class);
            return (AbstractRememberMeManager) dsm.getRememberMeManager();
        }
        return null;
    }

    private static void refreshJSFViewState(String path, HttpServletRequest request,
            HttpServletResponse response, Map<String, List<String>> formFields) throws IOException, ServletException {
        // view-state GET headers and cookies stay captured and are never applied to the browser response
        var htmlResponse = new FormResubmitResponse(response);
        forward(path, request, htmlResponse, HttpMethod.GET, Map.of());
        if (htmlResponse.getStatus() == SC_OK) {
            Optional.ofNullable(extractJSFNewViewState(htmlResponse.getBufferAsString())).ifPresent(viewState -> {
                log.debug("Replaced ViewState: {}", viewState);
                formFields.put(FACES_VIEW_STATE, List.of(viewState));
            });
        }
    }

    /**
     * @return view state of the first form in the rendered view, or null if there is none
     */
    static String extractJSFNewViewState(@NonNull String responseBody) {
        Elements elts = Jsoup.parse(responseBody).select("input[name=%s]".formatted(FACES_VIEW_STATE));
        return elts.isEmpty() ? null : Objects.requireNonNull(elts.first()).attr("value");
    }

    /**
     * Turns a Faces Ajax submission into a full-page submission of the same command.
     * The Ajax fields are only kept for stateless views, where they can't fail view state restoration.
     */
    static PartialAjaxResult noJSFAjaxRequests(Map<String, List<String>> formFields, boolean isStateless) {
        var fullForm = new LinkedHashMap<String, List<String>>();
        boolean hasPartialAjax = false;
        String facesSource = null;
        for (var field : formFields.entrySet()) {
            String name = field.getKey();
            boolean isSource = FACES_SOURCE.equals(name);
            if (isSource || Utils.startsWithOneOf(name, FACES_PARTIAL_PREFIX, FACES_BEHAVIOR_PREFIX)) {
                hasPartialAjax = true;
                if (isSource && !field.getValue().isEmpty() && !field.getValue().get(0).isEmpty()) {
                    facesSource = field.getValue().get(0);
                }
            } else {
                fullForm.put(name, field.getValue());
            }
        }
        var result = isStateless ? new LinkedHashMap<>(formFields) : fullForm;
        if (facesSource != null) {
            // The source value becomes the submitted command's parameter name
            result.putIfAbsent(facesSource, List.of(""));
        }
        return new PartialAjaxResult(result, hasPartialAjax, isStateless);
    }

    static boolean isJSFStatefulForm(@NonNull Map<String, List<String>> formFields) {
        return formFields.getOrDefault(FACES_VIEW_STATE, List.of()).stream()
                .anyMatch(viewState -> STATEFUL_VIEW_STATE_PATTERN.matcher(viewState).matches());
    }

    static boolean isJSFClientStateSavingMethod(ServletContext servletContext) {
        return STATE_SAVING_METHOD_CLIENT.equals(
                servletContext.getInitParameter(STATE_SAVING_METHOD_PARAM_NAME));
    }

    static boolean shouldSavePostData(HttpServletRequest request) {
        String secFetchSite = request.getHeader(SEC_FETCH_SITE);
        if (secFetchSite != null && !secFetchSite.isBlank()) {
            return "same-origin".equalsIgnoreCase(secFetchSite.trim());
        }

        return originMatchesRequest(request, request.getHeader(ORIGIN));
    }

    static boolean originMatchesRequest(HttpServletRequest request, String originHeader) {
        if (originHeader == null || originHeader.isBlank() || "null".equalsIgnoreCase(originHeader)) {
            return false;
        }

        try {
            URI origin = URI.create(originHeader);
            String originScheme = origin.getScheme();
            String originHost = origin.getHost();
            int originPort = normalizePort(originScheme, origin.getPort());

            String requestScheme = request.getScheme();
            String requestHost = request.getServerName();
            int requestPort = normalizePort(requestScheme, request.getServerPort());

            return Objects.equals(originScheme, requestScheme)
                    && Objects.equals(originHost, requestHost)
                    && originPort == requestPort;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static int normalizePort(String scheme, int port) {
        if (port >= 0) {
            return port;
        }
        if (HTTPS_SCHEME.equalsIgnoreCase(scheme)) {
            return DEFAULT_HTTPS_PORT;
        }
        if (HTTP_SCHEME.equalsIgnoreCase(scheme)) {
            return DEFAULT_HTTP_PORT;
        }
        return -1;
    }
}
