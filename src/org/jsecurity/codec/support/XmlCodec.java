package org.jsecurity.codec.support;

import org.jsecurity.codec.Codec;
import org.jsecurity.codec.DecoderException;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Converts Objects to and from Strings using a respective JavaBeans
 * {@link XMLEncoder XMLEncoder} and {@link XMLDecoder XMLDecoder}.
 *
 * @author Les Hazlewood
 * @since Feb 7, 2008 12:43:13 PM
 */
public class XmlCodec extends CodecSupport implements Codec {

    public Object encode(Object principals) {
        if (principals == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(bos));
        encoder.writeObject(principals);
        encoder.close();
        
        return toString( bos.toByteArray() );
    }

    public Object decode(String encoded) {
        byte[] bytes = toBytes( encoded );
        ByteArrayInputStream bis = new ByteArrayInputStream( bytes );
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(bis));
        Object o = decoder.readObject();
        decoder.close();
        return o;
    }

    public Object decode(Object encoded) {
        if (encoded == null) {
            String msg = "argument cannot be null.";
            throw new DecoderException(msg);
        }
        if (!(encoded instanceof String) ) {
            String msg = getClass().getName() + " implementation can only decode Strings.  " +
                "Argument supplied is of type [" + encoded.getClass().getName() + "]";
            throw new DecoderException( msg );
        }
        return decode( (String)encoded );
    }

}
