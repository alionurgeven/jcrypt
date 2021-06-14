package com.geven.jcrypt.encrypt;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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
public class Encrypt {
  public static final Logger LOGGER = LoggerFactory.getLogger(Encrypt.class);

  private PublicKey publicKey;

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public boolean setPublicKey(byte[] publicKeyData) {
    try {
      var x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyData);
      var keyFactory = KeyFactory.getInstance("RSA");
      setPublicKey(keyFactory.generatePublic(x509EncodedKeySpec));
      return true;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOGGER.error("error setting public-key ({})", e.getMessage());
      System.exit(1);
    }
    return false;
  }

  public byte[] encrypt(byte[] data) {
    try {
      var cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
      return cipher.doFinal(data);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
      LOGGER.error("error on cipher init ({})", e.getMessage());
      System.exit(1);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      LOGGER.error("error on encryption ({})", e.getMessage());
      System.exit(1);
    }
    return new byte[0];
  }
}
