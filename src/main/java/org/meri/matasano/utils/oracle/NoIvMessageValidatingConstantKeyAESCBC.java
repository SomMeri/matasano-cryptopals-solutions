package org.meri.matasano.utils.oracle;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.meri.matasano.utils.Ascii;
import org.meri.matasano.utils.encryption.AESCBC;
import org.meri.matasano.utils.encryption.CoreCipher;

public class NoIvMessageValidatingConstantKeyAESCBC implements EncryptingOracleCipher, CoreCipher {

  private final byte[] key;
  
  private AESCBC aescbc = new AESCBC();
  private PlaintextValidator validator = PlaintextValidator.ASCII_VALIDATOR;
  
  public NoIvMessageValidatingConstantKeyAESCBC(byte[] key) {
    this.key = key;
  }

  public NoIvMessageValidatingConstantKeyAESCBC() {
    RandomNumberGenerator generator = new SecureRandomNumberGenerator();
    this.key = generator.nextBytes(aescbc.getBlockSize()).getBytes();
  }

  public NoIvMessageValidatingConstantKeyAESCBC(AESCBC aescbc) {
    this();
    this.aescbc = aescbc;
  }

  public byte[] decrypt(byte[] ciphertext) throws InvalidPlaintextException {
    byte[] plaintext = aescbc.decrypt(ciphertext, key, key);
    validator.validate(plaintext);
    return plaintext;
  }

  public byte[] encrypt(byte[] plaintext) {
    return aescbc.encrypt(plaintext, key, key);
  }

  public int getBlockLength() {
    return aescbc.getBlockSize();
  }

  public interface PlaintextValidator {
    void validate(byte[] plaintext) throws InvalidPlaintextException;

    PlaintextValidator NULL_VALIDATOR = new PlaintextValidator() {
      public void validate(byte[] plaintext) {
      }
    };

    PlaintextValidator ASCII_VALIDATOR = new PlaintextValidator() {
      private Ascii ascii = new Ascii();

      public void validate(byte[] plaintext) {
        for (int i = 0; i < plaintext.length; i++) {
          byte letter = plaintext[i];
          if (!ascii.isUrlCharacter(letter))
            throw new InvalidPlaintextException(plaintext);
        }
      }
      
    };

  }
  
  @SuppressWarnings("serial")
  public static class InvalidPlaintextException extends RuntimeException {
    
    private final byte[] invalidPlaintext;

    public InvalidPlaintextException(byte[] invalidPlaintext) {
      super();
      this.invalidPlaintext = invalidPlaintext;
    }

    public byte[] getInvalidPlaintext() {
      return invalidPlaintext;
    }
    
  }

}
