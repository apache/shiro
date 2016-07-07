package org.apache.shiro.web.servlet;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.CipherService;
import org.apache.shiro.crypto.OperationMode;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.SimpleByteSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Enhanced implementation of {@link Cookie Cookie} supporting encryption semantics through a provided
 * {@link org.apache.shiro.crypto.CipherService}.
 *
 * Uses an {@link org.apache.shiro.crypto.AesCipherService} by default if none is set. The default cipher service is
 * configured to use a key size of 128 bits and the {@link org.apache.shiro.crypto.OperationMode} is set to CBC.
 *
 * @since 1.2
 */
public class EncryptedCookie extends SimpleCookie {
    /**
     * The key size for the default cipher service.
     */
    private static final int DEFAULT_CIPHER_SERVICE_KEY_SIZE = 128;

    /**
     * The cipher service to use for all crypto operations.
     */
    private CipherService cipherService;

    /**
     * The key to use for crypto operations.
     */
    private byte[] key;

    public EncryptedCookie() {
        this.cipherService = new AesCipherService();
        ((AesCipherService)cipherService).setKeySize(DEFAULT_CIPHER_SERVICE_KEY_SIZE);
        ((AesCipherService)cipherService).setMode(OperationMode.CBC);
    }

    @Override
    public String readValue(HttpServletRequest request, HttpServletResponse ignored) {

        String value = super.readValue(request, ignored);

        if (value != null) {
            value = decryptValue(value);
        }

        return value;
    }

    private String decryptValue(String value) {
        if (value != null) {
            byte[] base64DecodedEncryptedValue = Base64.decode(value);
            ByteSource decryptedByteSource = this.cipherService.decrypt(base64DecodedEncryptedValue, key);
            value = CodecSupport.toString(decryptedByteSource.getBytes());
        }

        return value;
    }

    @Override
    protected void addCookieHeader(HttpServletResponse response, String name, String value, String comment, String domain, String path, int maxAge, int version, boolean secure, boolean httpOnly) {
        String encryptedValue = encryptValue(value);
        super.addCookieHeader(response, name, encryptedValue, comment, domain, path, maxAge, version, secure, httpOnly);
    }

    private String encryptValue(String unencryptedValue) {
        ByteSource encryptedValue = this.cipherService.encrypt(ByteSource.Util.bytes(unencryptedValue).getBytes(), key);

        return encryptedValue.toBase64();
    }

    /**
     * Overrides the default implementation of the {@link org.apache.shiro.crypto.CipherService}.
     *
     * @param cipherService the implementation of {@link org.apache.shiro.crypto.CipherService} you want to use
     */
    public void setCipherService(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    /**
     * Accepts a base 64 encoded string representation of the key to be used for crypto operations
     *
     * @param key base 64 encoded key
     */
    public void setKey(String key) {
        this.key = Base64.decode(key);
    }

    /**
     * Sets the raw bytes representing the key to be used for crypto operations
     *
     * @param key they raw bytes for the key
     */
    public void setKey(byte[] key) {
        this.key = key;
    }
}
