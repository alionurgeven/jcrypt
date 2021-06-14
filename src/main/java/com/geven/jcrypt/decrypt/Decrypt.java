package com.geven.jcrypt.decrypt;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Slf4j
@Getter
@Setter
public class Decrypt {
  public static final Logger LOGGER = LoggerFactory.getLogger(Decrypt.class);

  private PrivateKey privateKey;

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public boolean setPrivateKey(byte[] privateKeyData) {
    try {
      var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
      var keyFactory = KeyFactory.getInstance("RSA");
      setPrivateKey(keyFactory.generatePrivate(pkcs8EncodedKeySpec));
      return true;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOGGER.error("error setting private-key ({})", e.getMessage());
      System.exit(1);
    }
    return false;
  }

  public byte[] decrypt(byte[] data) {
    try {
      var cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
      return cipher.doFinal(data);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
      LOGGER.error("error on cipher init ({})", e.getMessage());
      System.exit(1);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      LOGGER.error("error on decryption ({})", e.getMessage());
      System.exit(1);
    }
    return new byte[0];
  }
}
