// vi: ft=java
//
// V.2

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

    if (verbose) {
      print_byte_array("encrypted_password", encrypted_password);
      print_byte_array("salt              ", salt              );
      print_byte_array("key               ", key               );
    }


    System.arraycopy(db_system_id, 0, key, 0, db_system_id.length);
    System.arraycopy(salt, 0, key, db_system_id.length, salt.length);


    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
    for (int i=0; i<42; i++) {
      key = md.digest(key);
    }

    if (verbose) {
      print_byte_array("key (MD5'd)       ", key               );
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

    if (argv.length < 2) {
       System.out.println("arguments: [-v]  encrypted  db.system.id");
       return;
    }

    int pos_encrypted;
    int pos_db_system_id;

    if (argv[0].equals("-v")) {

      if (argv.length < 3) {
        System.out.println("arguments: [-v]  encrypted  db.system.id");
        return;
      }
      verbose = true;
      pos_encrypted    = 1;
      pos_db_system_id = 2;
      System.out.println("verbose flag was set");
    }
    else {
      pos_encrypted    = 0;
      pos_db_system_id = 1;
    }

    byte[] encrypted    = argv[pos_encrypted   ].getBytes();
    byte[] db_system_id = argv[pos_db_system_id].getBytes();


    byte[] x = decrypt_v4(encrypted, db_system_id);

    String password = new String(x);

    System.out.println(password);

    }
    catch (Exception e) {
      System.out.println(e.toString());
    }
  }

  private static boolean verbose = false;

  private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

  private static void print_byte_array(String what, byte[] array) {

    System.out.print(what);
    System.out.print(": ");

    char[] hex = new char[2];
    for (int i = 0; i < array.length; i++) {

      int v = array[i] & 0xFF;

      if (i > 0) {
         System.out.print(",");
      }
      hex[0] = HEX_ARRAY[v >>> 4];
      hex[1] = HEX_ARRAY[v & 0x0F];
      System.out.print(hex);
    }
    System.out.println();
  }
}
