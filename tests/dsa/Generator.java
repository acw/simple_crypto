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
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

class Generator {
  private FileWriter out;
  private SecureRandom rng;

  final static int NUM_THREADS = 4;

  public Generator(SecureRandom r, FileWriter o) {
    rng = r;
    out = o;
  }

  public void runTests(int lsize, int nsize, int count)
    throws IOException, InterruptedException
  {
    Thread threads[] = new Thread[NUM_THREADS];

    System.out.print("Generating L" + lsize + "N" + nsize + " tests ");
    for(int i = 0; i < NUM_THREADS; i++) {
      Runner runner = new Runner(lsize, nsize, count / NUM_THREADS, this);
      Thread runThread = new Thread(runner);
      runThread.start();
      threads[i] = runThread;
    }
    for(Thread thread : threads) {
      thread.join();
    }
    System.out.println(" done.");
  }

  public synchronized void output(DSAParameters params,
                                  AsymmetricCipherKeyPair kp,
                                  int digestsize,
                                  byte[] message,
                                  BigInteger[] rs)
    throws IOException
  {
    DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
    DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();
    out.write("p: " + params.getP().toString(16) + "\n");
    out.write("q: " + params.getQ().toString(16) + "\n");
    out.write("g: " + params.getG().toString(16) + "\n");
    out.write("x: " + priv.getX().toString(16) + "\n");
    out.write("y: " + pub.getY().toString(16) + "\n");
    out.write("h: " + digestsize + "\n");
    out.write("m: " + asHex(message) + "\n");
    out.write("r: " + rs[0].toString(16) + "\n");
    out.write("s: " + rs[1].toString(16) + "\n");
    out.flush();
    System.out.print(".");
    System.out.flush();
  }

  private Digest appropriateDigest(int nsize)
    throws IOException
  {
    switch(nsize) {
      case 1:   return new SHA1Digest();
      case 160: return new SHA1Digest();
      case 224: return new SHA224Digest();
      case 256: return new SHA256Digest();
      case 384: return new SHA384Digest();
      case 512: return new SHA512Digest();
      default:
        throw new IOException("Bad digest size!");
    }
  }

  private int randomDigestSize()
    throws IOException
  {
    switch(getRandomChoice(5)) {
        case 0: return 1;
        case 1: return 224;
        case 2: return 256;
        case 3: return 384;
        case 4: return 512;
        default:
          throw new IOException("The world broke.");
    }
  }

  private int getRandomChoice(int modulus) {
    byte randoms[] = new byte[2];
    rng.nextBytes(randoms);
    int random = ((int)randoms[0] << 8) + ((int)randoms[1]);
    return (Math.abs(random) % modulus);
  }

  private String asHex(byte[] data) {
    String result = "";

    for(byte value : data) {
      result = result + String.format("%02x", value);
    }

    return result;
  }

  public static void main(String[] args)
    throws IOException, InterruptedException
  {
    SecureRandom rng = new SecureRandom();
    FileWriter outfile = new FileWriter("signatures.test", false);
    Generator gen = new Generator(rng, outfile);

    gen.runTests(1024, 160, 500);
    gen.runTests(2047, 224, 500);
    gen.runTests(2048, 256, 250);
    gen.runTests(3072, 256, 100);
  }

  private class Runner implements Runnable {
    private int lsize;
    private int nsize;
    private int count;
    private Generator parent;

    public Runner(int lsize, int nsize, int count, Generator parent)
    {
      this.lsize = lsize;
      this.nsize = nsize;
      this.count = count;
      this.parent = parent;
    }

    public void run()
    {
      for(int i = 0; i < count; i++) {
        runTest();
      }
    }

    private void runTest()
    {
      try {
        DSAParameterGenerationParameters genparams =
          new DSAParameterGenerationParameters(lsize, nsize, 80, rng);
        DSAParametersGenerator gen =
          new DSAParametersGenerator(parent.appropriateDigest(nsize));
        gen.init(genparams);
        DSAParameters params = gen.generateParameters();
        DSAKeyGenerationParameters dsakeygenparams =
          new DSAKeyGenerationParameters(rng, params);
        DSAKeyPairGenerator keygen = new DSAKeyPairGenerator();
        keygen.init(dsakeygenparams);
        AsymmetricCipherKeyPair kp = keygen.generateKeyPair();
        DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
        DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();
        int msgsize = getRandomChoice(1024);
        byte message[] = new byte[msgsize];
        rng.nextBytes(message);
        int digestsize = randomDigestSize();
        Digest msgdigest = appropriateDigest(digestsize);
        HMacDSAKCalculator kgen = new HMacDSAKCalculator(msgdigest);
        DSASigner signer = new DSASigner(kgen);
        signer.init(true, priv);
        BigInteger rs[] = signer.generateSignature(message);
        parent.output(params, kp, digestsize, message, rs);
      } catch(IOException exc) {
        System.out.println("EXCEPTION!");
        run();
      }
    }
  }
}
