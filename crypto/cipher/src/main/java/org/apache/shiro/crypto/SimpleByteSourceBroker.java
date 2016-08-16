package org.apache.shiro.crypto;

import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.ByteSourceWrapper;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Destroyable;

import java.io.IOException;

/**
 * A simple implementation that maintains cipher service, ciphertext and key for decrypting it later.
 * {@link #useBytes(ByteSourceUser)} guarantees the sensitive data in byte array will be erased at end of use.
 */
public class SimpleByteSourceBroker implements ByteSourceBroker, Destroyable {
    private JcaCipherService cipherService;
    private byte[] ciphertext;
    private byte[] key;
    private boolean destroyed = false;

    public SimpleByteSourceBroker(JcaCipherService cipherService, byte[] ciphertext, byte[] key) {
        this.cipherService = cipherService;
        this.ciphertext = ciphertext.clone();
        this.key = key.clone();
    }

    public synchronized void useBytes(ByteSourceUser user) {
        if (destroyed || user == null) {
            return;
        }
        ByteSource byteSource = cipherService.decryptInternal(ciphertext, key);

        try (ByteSourceWrapper temp = ByteSourceWrapper.wrap(byteSource.getBytes())) {
            user.use(temp.getBytes());
        } catch (IOException e) {
            // ignore
        }

    }

    public byte[] getClonedBytes() {
        ByteSource byteSource = cipherService.decryptInternal(ciphertext, key);
        return byteSource.getBytes(); // this's a newly created byte array
    }

    public void destroy() throws Exception {
        if (!destroyed) {
            synchronized (this) {
                destroyed = true;
                cipherService = null;
                CollectionUtils.wipe(ciphertext);
                ciphertext = null;
                CollectionUtils.wipe(key);
                key = null;
            }
        }
    }
}
