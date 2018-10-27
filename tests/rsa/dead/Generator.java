// Just because I always forget Java compilation:
//    javac Generator.java -cp bcprov-ext-jdk15on-159.jar
//    java -cp "bcprov-ext-jdk15on-159.jar:." Generator
// Also, go here:
//    https://www.bouncycastle.org/latest_releases.html
//
import java.io.FileWriter;
import java.io.IOException;
import java.lang.InterruptedException;
import java.lang.Math;
import java.lang.Thread;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Generator
{
    public final static int[] KEY_SIZES = {512,1024,2048,3072,4096,8192,15360};
    public final static int   RUN_COUNT = 1;//750;
    public final static int   THREADS   = 4;

    private SecureRandom rng;
    private FileWriter outf;

    public Generator(SecureRandom rng, FileWriter outf)
    {
      this.rng = rng;
      this.outf = outf;
    }

    synchronized public void output(RSAPrivateKey key,
                                    String digest,
                                    byte[] message,
                                    byte[] signature,
                                    byte[] cipher)
    {
      try {
        this.outf.write("d: " + key.getPrivateExponent().toString(16) + "\n");
        this.outf.write("n: " + key.getModulus().toString(16) + "\n");
        this.outf.write("h: " + digest.substring(3) + "\n");
        this.outf.write("m: " + asHex(message) + "\n");
        this.outf.write("s: " + asHex(signature) + "\n");
        this.outf.write("c: " + asHex(cipher) + "\n");
        System.out.print(".");
        this.outf.flush();
        System.out.flush();
      } catch(IOException e) {
        System.out.println("EXCEPTION: " + e);
      }
    }

    private String asHex(byte[] data) {
      String result = "";

      for(byte value : data) {
        result = result + String.format("%02x", value);
      }

      return result;
    }


    public void run(int size)
      throws InterruptedException
    {
      Thread threads[] = new Thread[THREADS];

      for(int i = 0; i < THREADS; i++) {
        Runner runner = new Runner(size);
        Thread runThread = new Thread(runner);
        runThread.start();
        threads[i] = runThread;
      }
      for(Thread t : threads) { t.join(); }
    }

    public static void main(String[] args)
      throws IOException, InterruptedException
    {
      SecureRandom rng = new SecureRandom();

      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      for(int size : KEY_SIZES) {
        System.out.print("Generating " + size + "-bit RSA tests ");
        FileWriter sig = new FileWriter("rsa" + size + ".test");

        Generator gen = new Generator(rng, sig);
        gen.run(size);

        sig.close();
        System.out.println(" done.");
      }
    }

    private class Runner implements Runnable
    {
      private int size;

      public Runner(int size)
      {
        this.size = size;
      }

      private KeyPair generateKey()
        throws NoSuchAlgorithmException, NoSuchProviderException
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(this.size, rng);
        KeyPair kp = generator.generateKeyPair();
        return kp;
      }

      private byte[] generateBlock(int maxSize)
      {
        int size = rng.nextInt(maxSize);
        byte message[] = new byte[size];
        rng.nextBytes(message);
        return message;
      }

      private String randomDigest()
      {
        switch(rng.nextInt(5)) {
          case 0: return "SHA1";
          case 1: return "SHA224";
          case 2: return "SHA256";
          case 3: return "SHA384";
          case 4: return "SHA512";
          default:
            return null;
        }
      }

      private String signingAlgorithm(String digest)
      {
        return (digest + "withRSA");
      }

      private String encryptAlgorithm(String digest)
      {
        return ("RSA/None/OAEPWith" + digest + "AndMGF1Padding");
      }

      private byte[] sign(String algo, RSAPrivateKey key, byte[] msg)
        throws IllegalArgumentException, SignatureException,
               InvalidKeyException, NoSuchAlgorithmException
      {
        Signature sig = Signature.getInstance(signingAlgorithm(algo));
        sig.initSign(key, rng);
        sig.update(msg);
        return sig.sign();
      }

      private byte[] encrypt(String algo, RSAPrivateKey key, byte[] msg)
        throws IllegalArgumentException, NoSuchAlgorithmException,
               NoSuchProviderException, InvalidKeyException,
               IllegalBlockSizeException, NoSuchPaddingException,
               BadPaddingException
      {
        Cipher cipher = Cipher.getInstance(encryptAlgorithm(algo), "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(msg);
      }

      public void run()
      {
        int i = 0;

        while(i < RUN_COUNT) {
          try {
            KeyPair kpair     = this.generateKey();
            RSAPrivateKey key = (RSAPrivateKey)kpair.getPrivate();
            byte[]  msg       = this.generateBlock(1024);
            String  digest    = this.randomDigest();
            byte[]  sig       = this.sign(digest, key, msg);
            byte[]  enc       = this.encrypt(digest, key, msg);
            output(key, digest, msg, sig, enc);
            i = i + 1;
          } catch(Exception e) {
            System.out.println("Exception: " + e);
          }
        }
      }
    }
}
