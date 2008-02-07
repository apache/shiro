package org.jsecurity.context.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Codec;
import org.jsecurity.codec.CodecException;
import org.jsecurity.codec.support.CodecSupport;
import org.jsecurity.codec.support.XmlCodec;
import org.jsecurity.crypto.SymmetricCipher;
import org.jsecurity.crypto.support.SimpleBlowfishCipher;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Feb 7, 2008 2:56:48 PM
 */
public class RememberMeSerializer implements PrincipalsSerializer {

    private transient final Log log = LogFactory.getLog(getClass());

    private Codec codec = new XmlCodec();
    private SymmetricCipher cipher = new SimpleBlowfishCipher();

    public RememberMeSerializer(){}

    public Codec getCodec() {
        return codec;
    }

    public void setCodec(Codec codec) {
        this.codec = codec;
    }

    public SymmetricCipher getCipher() {
        return cipher;
    }

    public void setCipher(SymmetricCipher cipher) {
        this.cipher = cipher;
    }

    protected String encode(Object principals) {
        Object encoded = getCodec().encode(principals);
        if (!(encoded instanceof String)) {
            String msg = "Codec of type [" + getCodec().getClass().getName() + "] did not encode " +
                "the principals argument to a String.  The " + getClass().getName() +
                "implementation requires a String return type.";
            throw new CodecException(msg);
        }
        return (String)encoded;
    }

    protected Object decode( String source ) {
        return getCodec().decode( source );
    }

    protected byte[] encrypt(String serialized) {
        SymmetricCipher cipher = getCipher();
        if (log.isDebugEnabled()) {
            log.debug("Using Cipher [" + cipher + "] to encrypt encoded principals String.");
        }
        byte[] serializedBytes = CodecSupport.toBytes(serialized);
        return cipher.encrypt(serializedBytes);
    }

    protected String decrypt(byte[] encrypted) {
        SymmetricCipher cipher = getCipher();
        byte[] decryptedBytes = cipher.decrypt(encrypted);
        return toString(decryptedBytes);
    }

    protected String toString(byte[] bytes) {
        return Base64.encodeBase64ToString(bytes);
    }

    protected byte[] toBytes(String string) {
        return Base64.decodeBase64(string);
    }

    public String serialize(Object principals) {
        String output = encode(principals);
        SymmetricCipher cipher = getCipher();
        if (cipher != null) {
            byte[] outputBytes = encrypt(output);
            output = toString(outputBytes);
        } else {
            if (log.isDebugEnabled()) {
                String msg = "No Cipher set as a property of this class.  The codec encoded data " +
                    "will not be encrypted.";
                log.debug(msg);
            }
        }

        return output;
    }

    public Object deserialize(String encoded) {
        if ( encoded == null ) {
            String msg = "Method argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        String source = encoded;
        SymmetricCipher cipher = getCipher();
        if ( cipher != null ) {
            byte[] encryptedBytes = toBytes( encoded );
            source = decrypt( encryptedBytes );
        }
        return decode( source );
    }
}
