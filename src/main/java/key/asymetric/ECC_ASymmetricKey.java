package key.asymetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECC_ASymmetricKey {

    public static void main(String[] argv) {

        try {

            // BouncyCastle is a Java library that complements the default Java Cryptographic Extension (JCE).
            Security.addProvider(new BouncyCastleProvider());

            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
//            ecKeyGen.initialize(new ECGenParameterSpec("brainpoolP384r1"));
            ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));

            // doesn't work, which means we are dancing on the leading edge :)
            // KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            // ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));

            KeyPair pair = ecKeyGen.generateKeyPair();


            // We'll use the public key to encrypt the data and the private one for decrypting it
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();


            Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");

            // Initialize the cipher for encryption with a public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);


            //sensitive information
            byte[] text = "No body can see me".getBytes();

            System.out.println("Text [Byte Format] : " + text);
            System.out.println("Text : " + new String(text));

            // Encrypt the text
            byte[] textEncrypted = cipher.doFinal(text);

            System.out.println("Text Encrypted : " + textEncrypted);

            // Initialize the same cipher for decryption with a private key
//            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate(), cipher.getParameters());

            // Decrypt the text
            byte[] textDecrypted = cipher.doFinal(textEncrypted);

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
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }
}
