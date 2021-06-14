package com.geven.jcrypt;

import com.geven.jcrypt.decrypt.Decrypt;
import com.geven.jcrypt.encrypt.Encrypt;
import com.sun.tools.javac.Main;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class JcryptApplication {

  private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) {
    SpringApplication.run(JcryptApplication.class, args);


    // For encrypting with a public key
    LOGGER.info("encrypt");
    Encrypt encrypt = new Encrypt();

    // read and set public-key
    LOGGER.info("reading public-key");
    byte[] publicKeyData = readFile("FILE_NAME_HERE");
    LOGGER.info("setting public-key");
    encrypt.setPublicKey(publicKeyData);

    // read input
    LOGGER.info("reading input");
    byte[] inputData = readFile("FILE_NAME_HERE");

    // encrypt
    LOGGER.info("encrypting...");

    // ENCRYPTED DATA
    byte[] outputData = encrypt.encrypt(inputData);

    LOGGER.info(Arrays.toString(outputData));

    // For decrypting with a private key

    LOGGER.info("decrypt");
    Decrypt decrypt = new Decrypt();

    // read and set private-key
    LOGGER.info("reading private-key");
    byte[] privateKeyData = readFile("FILE_NAME_HERE");
    LOGGER.info("setting private-key");
    decrypt.setPrivateKey(privateKeyData);

    // read input
    LOGGER.info("reading input");
    byte[] inputData2 = readFile("FILE_NAME_HERE");

    // decrypt
    LOGGER.info("decrypting...");

    // DECRYPTED DATA
    byte[] outputData2 = decrypt.decrypt(inputData2);

  }

  public static byte[] readFile(String fileName) {
    LOGGER.info("reading from file '{}'", fileName);
    try {
      byte[] data = FileUtils.readFileToByteArray(new File(fileName));
      return data;
    } catch (IOException e) {
      LOGGER.error("error reading from file '{}' ({})", fileName, e.getMessage());
    }
    return null;
  }

}
