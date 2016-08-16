package org.apache.shiro.crypto;

/**
 * {@link ByteSourceBroker#useBytes(ByteSourceUser)} method requires ByteSourceUser argument,
 * and developers should implement how we use the byte arrays in our code-base.
 * <br/>
 * The byte array "bytes" could be a decrypted password in plaintext format, or other
 * sensitive information that needs to be erased at end of use.
 */
public interface ByteSourceUser {
    void use(byte[] bytes);
}
