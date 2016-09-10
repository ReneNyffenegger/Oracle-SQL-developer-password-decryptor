// vi: ft=java

import java.security.MessageDigest;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

//     Requires Java 8:
import java.util.Base64;


public class Decrypt_V4 {

  private static byte[] des_cbc_decrypt(
       byte[] encrypted_password,
       byte[] decryption_key,
       byte[] iv)
  throws GeneralSecurityException
  {

    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryption_key, "DES"), new IvParameterSpec(iv));
    return cipher.doFinal(encrypted_password);

  }

  private static byte[] decrypt_v4(
      byte[] encrypted,
      byte[] db_system_id)
  throws GeneralSecurityException
  {

    byte[] encrypted_password = Base64.getDecoder().decode(encrypted);

    byte[] salt = DatatypeConverter.parseHexBinary("051399429372e8ad");

 // key = db_system_id + salt
    byte[] key = new byte[db_system_id.length + salt.length];
    System.arraycopy(db_system_id, 0, key, 0, db_system_id.length);
    System.arraycopy(salt, 0, key, db_system_id.length, salt.length);


    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
    for (int i=0; i<42; i++) {
      key = md.digest(key);
    }

 // secret_key = key [0..7]
    byte[] secret_key = new byte[8];
    System.arraycopy(key, 0, secret_key, 0, 8);

 // iv = key [8..]
    byte[] iv = new byte[key.length - 8];
    System.arraycopy(key, 8, iv, 0, key.length - 8);

    return des_cbc_decrypt(encrypted_password, secret_key, iv);

  }


  public static void main(String[] argv) { try {

    byte[] encrypted    = argv[0].getBytes();
    byte[] db_system_id = argv[1].getBytes();

    byte[] x = decrypt_v4(encrypted, db_system_id);

    String password = new String(x);

    System.out.println(password);

    }
    catch (Exception e) {
      System.out.println(e.toString());
    }

  }

}
