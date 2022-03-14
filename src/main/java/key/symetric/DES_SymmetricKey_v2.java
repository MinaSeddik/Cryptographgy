package key.symetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DES_SymmetricKey_v2 {

    public static void main(String[] argv) {

        try {

            // DES uses a 56-bit key: 8 bytes where one bit in each byte is a parity bit.
            byte[] secretKey = "12345678".getBytes();
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "DES");

            byte[] iv = "a76nb5h9".getBytes();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);


            /*
                DES = Data Encryption Standard.
                CBC = Electronic Codebook mode.
                PKCS5Padding = PKCS #5-style padding.
             */
            Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");


            desCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);


            //sensitive information
            byte[] text = "No body can see me".getBytes();

            System.out.println("Text [Byte Format] : " + text);
            System.out.println("Text : " + new String(text));

            // Encrypt the text
            byte[] textEncrypted = desCipher.doFinal(text);

            System.out.println("Text Encrypted : " + textEncrypted);

            // Initialize the same cipher for decryption
            desCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

            // Decrypt the text
            byte[] textDecrypted = desCipher.doFinal(textEncrypted);

            System.out.println("Text Decrypted : " + new String(textDecrypted));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }
}
