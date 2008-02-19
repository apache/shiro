/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.crypto;

/**
 * A <tt>Cipher</tt> is an algorithm used in cryptography that converts an original input source using a <tt>Key</tt> to
 * an uninterpretable format.  The resulting encrypted output is only able to be converted back to original form with
 * a <tt>Key</tt> as well.
 *
 * <p>In what is known as <em>Symmetric</em> <tt>Cipher</tt>s, the <tt>Key</tt> used to encrypt the source is the same
 * <tt>Key</tt> used to decrypt it.
 *
 * <p>In <em>Assymetric</em> <tt>Cipher</tt>s, the encryption <tt>Key</tt> is not the same as the decryption <tt>Key</tt>.
 * The most common type of Assymetric Ciphers are based on what is called public/private key pairs:
 *
 * <p>A <em>private</em> key is known only to a single party, and as its name implies, is supposed be kept very private
 * and secure.  A <em>public</em> key that is associated with the private key can be disseminated freely to anyone.
 * Then data encrypted by the public key can only be decrypted by the private key and vice versa, but neither party
 * need share their private key with anyone else.  By not sharing a private key, you can guarantee no 3rd party can
 * intercept the key and therefore use it to decrypt a message.
 *
 * <p>This assymetric key technology was created as a
 * more secure alternative to symmetric ciphers that sometimes suffer from man-in-the-middle attacks since, for
 * data shared between two parties, the same Key must also be shared and may be compromised.
 *
 * <p>Note that a symmetric cipher is perfectly fine to use if you just want to encode data in a format no one else
 * can understand and you never give away the key.  JSecurity uses a symmetric cipher when using certain
 * HTTP Cookies for example - because it is often undesireable to have user's identity stored in a plain-text cookie,
 * that identity can be converted via a symmetric cipher.  Since the the same exact JSecurity application will receive
 * the cookie, it can decrypt it via the same <tt>Key</tt> and there is no potential for discovery since that Key
 * is never shared with anyone.
 *
 * @see SimpleBlowfishCipher
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface Cipher {

    byte[] encrypt( byte[] raw, Key encryptionKey );

    byte[] decrypt( byte[] encrypted, Key decryptionKey );

}
