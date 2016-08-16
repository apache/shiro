package org.apache.shiro.crypto;

/**
 * ByteSourceBroker holds an encrypted value to decrypt it on demand.
 * <br/>
 * {@link #useBytes(ByteSourceUser)} method is designed for dictating
 * developers to use the byte source in a special way, to prevent its prevalence
 * and difficulty of managing & zeroing that critical information at end of use.
 * <br/>
 * For exceptional cases we allow developers to use the other method,
 * {@link #getClonedBytes()}, but it's not advised.
 */
public interface ByteSourceBroker {
    /**
     * This method accepts an implementation of ByteSourceUser functional interface.
     * <br/>
     * To limit the decrypted value's existence, developers should maintain the
     * implementation part as short as possible.
     *
     * @param user Implements a use-case for the decrypted value.
     */
    void useBytes(ByteSourceUser user);

    /**
     * As the name implies, this returns a cloned byte array
     * and caller has a responsibility to wipe it out at end of use.
     */
    byte[] getClonedBytes();
}
