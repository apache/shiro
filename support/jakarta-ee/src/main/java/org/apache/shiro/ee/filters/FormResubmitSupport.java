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
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.CONTENT_TYPE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpHeaderConstants.LOCATION;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpResponseCodes.FOUND;
import static org.apache.shiro.ee.filters.FormResubmitSupport.HttpResponseCodes.OK;
import static org.apache.shiro.ee.filters.FormResubmitSupport.MediaType.TEXT_XML;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.addCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.deleteCookie;
import static org.apache.shiro.ee.filters.FormResubmitSupportCookies.getCookieAge;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitDisabled;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.StringJoiner;
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
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.ToString;
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
import org.omnifaces.util.Servlets;
import org.owasp.encoder.Encode;

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
    private static final String FACES_VIEW_STATE_EQUALS = FACES_VIEW_STATE + "=";
    private static final Pattern VIEW_STATE_PATTERN
            = Pattern.compile(String.format("(.*)(%s-?\\d+:-?\\d+)(.*)", FACES_VIEW_STATE_EQUALS));
    private static final String FACES_SOURCE = "jakarta.faces.source";
    private static final String SEC_FETCH_SITE = "Sec-Fetch-Site";
    private static final String ORIGIN = "Origin";
    private static final String CACHE_CONTROL = "Cache-Control";
    private static final String NO_STORE = "no-store";
    private static final String PRAGMA = "Pragma";
    private static final String EXPIRES = "Expires";
    private static final String NO_CACHE = "no-cache";

    static class HttpMethod {
        static final String GET = "GET";
        static final String POST = "POST";
    }

    static class HttpHeaderConstants {
        static final String CONTENT_TYPE = "Content-Type";
        static final String LOCATION = "Location";
    }

    static class MediaType {
        static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
        static final String TEXT_XML = "text/xml";
    }

    static class HttpResponseCodes {
        static final int OK = 200;
        static final int FOUND = 302;
    }

    @RequiredArgsConstructor
    @EqualsAndHashCode @ToString
    @SuppressWarnings("VisibilityModifier")
    static class PartialAjaxResult {
        public final String result;
        public final boolean isPartialAjaxRequest;
        public final boolean isStatelessRequest;
    }

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
        if (request instanceof HttpServletRequest) {
            return HttpMethod.POST.equalsIgnoreCase(WebUtils.toHttp(request).getMethod());
        } else {
            return false;
        }
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
            String query = uri.getRawQuery();
            return query == null ? rawPath : rawPath + "?" + query;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Redirects the user to saved request after login, if available
     * Resubmits the form that caused the logout upon successful login.Form resubmission supports JSF and Ajax forms
     * @param request
     * @param response
     * @param useFallbackPath predicate whether to use fall back path
     * @param fallbackPath
     * @param resubmit if true, attempt to resubmit the form that was unsubmitted prior to logout
     */
    @SneakyThrows({IOException.class, ServletException.class})
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
     * @param request
     * @param response
     * @param useFallbackPath
     * @param fallbackPath
     */
    static void redirectToSaved(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallbackPath, String fallbackPath) {
        redirectToSaved(request, response, useFallbackPath, fallbackPath,
                !isFormResubmitDisabled(request.getServletContext()));
    }


    private static void doRedirectToSaved(HttpServletRequest request, HttpServletResponse response,
            @NonNull String savedRequest, boolean resubmit) throws IOException, ServletException {
        deleteCookie(response, request.getServletContext(), WebUtils.SAVED_REQUEST_KEY);
        String savedFormDataKeyString = Servlets.getRequestCookie(request, SHIRO_FORM_DATA_KEY);
        boolean doRedirectAtEnd = true;
        if (savedFormDataKeyString != null && resubmit) {
            AtomicReference<Cache<Object, ?>> cache = new AtomicReference<>();
            UUID savedFormDataKey = UUID.fromString(savedFormDataKeyString);
            String formData = getSavedFormDataFromKey(savedFormDataKey, cache::set);
            try {
                if (formData != null) {
                    Optional.ofNullable(resubmitSavedForm(formData, savedRequest, request, response,
                                    request.getServletContext(), false, true))
                            .ifPresent(path -> doFacesRedirect(request, response, path));
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
     * @param request
     * @param response
     */
    static void redirectToView(HttpServletRequest request, HttpServletResponse response) {
        redirectToView(request, response, (path, req) -> false, null);
    }

    /**
     * redirects to current view after a form submit,
     * or the fallback path if predicate succeeds
     *
     * @param request
     * @param response
     * @param useFallbackPath
     * @param fallbackPath
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
     * @param request
     * @param response
     * @param path
     * @param paramValues
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

    static String resubmitSavedForm(@NonNull String savedFormData, @NonNull String rawSavedRequest,
            HttpServletRequest originalRequest, HttpServletResponse originalResponse,
            ServletContext servletContext, boolean rememberedAjaxResubmit, boolean redirect)
            throws ServletException, IOException {
        if (FormResubmitRequest.isResubmit(originalRequest)) {
            throw new ServletException("Recursive form resubmission");
        }
        String savedRequest = normalizeSavedRequest(rawSavedRequest, originalRequest);
        if (savedRequest == null) {
            log.debug("Form resubmit: rejecting saved request");
            return originalRequest.getContextPath();
        }
        String dispatchPath = getDispatchPath(savedRequest, originalRequest);
        if (dispatchPath == null) {
            return originalRequest.getContextPath();
        }
        // These must be written before the final forward can commit the response.
        deleteCookie(originalResponse, servletContext, SHIRO_FORM_DATA_KEY);
        setNoStoreHeaders(originalResponse);
        PartialAjaxResult formData = parseFormData(savedFormData, dispatchPath, originalRequest,
                originalResponse, servletContext);
        boolean doubleSubmit = rememberedAjaxResubmit && !formData.isStatelessRequest;
        if (formData.isPartialAjaxRequest || doubleSubmit) {
            var response = new FormResubmitResponse(originalResponse);
            forward(dispatchPath, originalRequest, response, HttpMethod.POST, formData.result);
            response.copyCookiesTo(originalResponse);
            if (doubleSubmit && (response.getStatus() == OK || response.getStatus() == FOUND)) {
                // This second POST only obtains redirect handling for the expired Ajax view.
                // Its flash cookie must not replace the successful POST's messages.
                response = new FormResubmitResponse(originalResponse);
                forward(dispatchPath, originalRequest, response, HttpMethod.POST, savedFormData);
            }
            processResubmitResponse(response, originalResponse, savedRequest, rememberedAjaxResubmit, redirect);
        } else {
            forward(dispatchPath, originalRequest, originalResponse, HttpMethod.POST, formData.result);
        }
        if (hasFacesContext()) {
            Faces.responseComplete();
        }
        return null;
    }

    private static String getDispatchPath(String savedRequest, HttpServletRequest request) {
        String path = savedRequest.substring(request.getContextPath().length());
        if (path.isEmpty() || path.startsWith("?")) {
            path = "/" + path;
        }
        // A dispatcher can reach these directories, unlike the browser request being replayed.
        String decodedPath = URI.create(path).getPath();
        if (Pattern.compile("^/(WEB-INF|META-INF)([/;].*)?$", Pattern.CASE_INSENSITIVE).matcher(decodedPath).matches()) {
            return null;
        }
        return path;
    }

    private static void forward(String path, HttpServletRequest originalRequest, HttpServletResponse response,
            String method, String body) throws ServletException, IOException {
        var dispatcher = originalRequest.getServletContext().getRequestDispatcher(path);
        if (dispatcher == null) {
            throw new ServletException("No request dispatcher for saved form path: " + path);
        }
        var request = new FormResubmitRequest(originalRequest, path, method, body);
        // FacesServlet creates/releases its own context. Restore a calling JSF login action afterwards.
        FacesContext context = hasFacesContext() ? Faces.getContext() : null;
        try {
            if (context != null) {
                FacesContextAccess.restore(null);
            }
            dispatcher.forward(request, response);
        } finally {
            if (context != null) {
                FacesContextAccess.restore(context);
            }
        }
    }

    private abstract static class FacesContextAccess extends FacesContext {
        static void restore(FacesContext context) {
            setCurrentInstance(context);
        }
    }

    private static PartialAjaxResult parseFormData(String savedFormData, String path,
            HttpServletRequest request, HttpServletResponse response, ServletContext servletContext)
            throws IOException, ServletException {
        boolean isStateless = true;
        if (!isJSFClientStateSavingMethod(servletContext)) {
            String decodedFormData = URLDecoder.decode(savedFormData, StandardCharsets.UTF_8);
            if (isJSFStatefulForm(decodedFormData)) {
                isStateless = false;
                savedFormData = getJSFNewViewState(path, request, response, savedFormData);
            }
        }
        return noJSFAjaxRequests(savedFormData, isStateless);
    }

    private static void processResubmitResponse(FormResubmitResponse response, HttpServletResponse originalResponse,
            String savedRequest, boolean rememberedAjaxResubmit, boolean redirect) throws IOException {
        response.copyHeadersTo(originalResponse);
        int status = response.getStatus();
        originalResponse.setStatus(rememberedAjaxResubmit && status == FOUND ? OK : status);
        if (status == FOUND || status == OK && redirect) {
            originalResponse.setHeader("Content-Length", null);
            if (rememberedAjaxResubmit) {
                originalResponse.setHeader(LOCATION, null);
            }
            originalResponse.setHeader(CONTENT_TYPE, TEXT_XML);
            originalResponse.setCharacterEncoding(StandardCharsets.UTF_8.name());
            originalResponse.getWriter().append(String.format(
                    "<partial-response><redirect url=\"%s\"></redirect></partial-response>",
                    Encode.forXmlAttribute(savedRequest)));
        } else {
            originalResponse.setCharacterEncoding(response.getCharacterEncoding());
            originalResponse.getOutputStream().write(response.getBody());
        }
    }

    private static void setNoStoreHeaders(HttpServletResponse response) {
        response.setHeader(CACHE_CONTROL, NO_STORE);
        response.setHeader(PRAGMA, NO_CACHE);
        response.setDateHeader(EXPIRES, 0);
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

    private static String getJSFNewViewState(String path, HttpServletRequest request,
            HttpServletResponse response, String savedFormData) throws IOException, ServletException {
        var htmlResponse = new FormResubmitResponse(response);
        forward(path, request, htmlResponse, HttpMethod.GET, "");
        htmlResponse.copyCookiesTo(response);
        if (htmlResponse.getStatus() == OK) {
            String html = htmlResponse.getBodyAsString();
            // Decode only the view-state field: decoding the entire body corrupts escaped &, + and = in user input.
            savedFormData = java.util.Arrays.stream(savedFormData.split("&", -1)).map(field -> {
                String[] pair = field.split("=", 2);
                if (pair.length == 2 && FACES_VIEW_STATE.equals(URLDecoder.decode(pair[0], StandardCharsets.UTF_8))) {
                    String updated = extractJSFNewViewState(html,
                            FACES_VIEW_STATE_EQUALS + URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
                    return pair[0] + "=" + URLEncoder.encode(updated.substring(FACES_VIEW_STATE_EQUALS.length()),
                            StandardCharsets.UTF_8);
                }
                return field;
            }).collect(Collectors.joining("&"));
        }
        return savedFormData;
    }

    static String extractJSFNewViewState(@NonNull String responseBody, @NonNull String savedFormData) {
        Elements elts = Jsoup.parse(responseBody).select("input[name=%s]".formatted(FACES_VIEW_STATE));
        if (!elts.isEmpty()) {
            String viewState = elts.first().attr("value");

            var matcher = VIEW_STATE_PATTERN.matcher(savedFormData);
            if (matcher.matches()) {
                savedFormData = matcher.replaceFirst("$1%s%s$3".formatted(
                        FACES_VIEW_STATE_EQUALS, viewState));
                log.debug("Encoded w/Replaced ViewState: {}", savedFormData);
            }
        }
        return savedFormData;
    }

    static PartialAjaxResult noJSFAjaxRequests(String savedFormData, boolean isStateless) {
        boolean hasPartialAjax = false;
        String appendFacesSourceString = "";
        var fullForm = new StringJoiner("&");
        for (String field : savedFormData.split("&")) {
            String[] pair = field.split("=", 2);
            String name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            boolean isSource = FACES_SOURCE.equals(name);
            if (isSource || name.startsWith("jakarta.faces.partial.") || name.startsWith("jakarta.faces.behavior.")) {
                hasPartialAjax = true;
                if (isSource && pair.length == 2 && !pair[1].isEmpty()) {
                    // The source value becomes the submitted command's parameter name, still URL-encoded.
                    appendFacesSourceString = "&" + pair[1] + "=";
                }
            } else if (!field.isEmpty()) {
                fullForm.add(field);
            }
        }
        return new PartialAjaxResult((isStateless ? savedFormData : fullForm.toString())
                + appendFacesSourceString, hasPartialAjax, isStateless);
    }

    static boolean isJSFStatefulForm(@NonNull String savedFormData) {
        var matcher = VIEW_STATE_PATTERN.matcher(savedFormData);
        return matcher.find() && matcher.groupCount() >= 2
                && !matcher.group(2).equalsIgnoreCase("stateless");
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
