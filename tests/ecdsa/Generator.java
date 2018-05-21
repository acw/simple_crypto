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
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

class Generator {
  private FileWriter out;
  private SecureRandom rng;

  final static int NUM_THREADS = 4;

  public Generator(SecureRandom r, FileWriter o) {
    rng = r;
    out = o;
  }

  public void runTests(String curveName, int count)
    throws IOException, InterruptedException
  {
    Thread threads[] = new Thread[NUM_THREADS];

    System.out.print("Generating " + curveName + " tests ");
    for(int i = 0; i < NUM_THREADS; i++) {
      X9ECParameters x9ECParameters = NISTNamedCurves.getByName(curveName);
      ECDomainParameters params = new ECDomainParameters(x9ECParameters.getCurve(),
                                                         x9ECParameters.getG(),
                                                         x9ECParameters.getN());
      Runner runner = new Runner(params, count / NUM_THREADS, this);
      Thread runThread = new Thread(runner);
      runThread.start();
      threads[i] = runThread;
    }
    for(Thread thread : threads) {
      thread.join();
    }
    System.out.println(" done.");
  }

  public synchronized void output(AsymmetricCipherKeyPair kp,
                                  int digestsize,
                                  byte[] message,
                                  BigInteger[] rs)
    throws IOException
  {
    ECPublicKeyParameters pub = (ECPublicKeyParameters)kp.getPublic();
    ECPrivateKeyParameters priv = (ECPrivateKeyParameters)kp.getPrivate();
    out.write("c: " + pub.getParameters().getCurve().getFieldSize() + "\n");
    out.write("x: " + pub.getQ().getAffineXCoord().toBigInteger().toString(16) + "\n");
    out.write("y: " + pub.getQ().getAffineYCoord().toBigInteger().toString(16) + "\n");
    out.write("d: " + priv.getD().toString(16) + "\n");
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
    FileWriter outfile = new FileWriter("signature.test", false);
    Generator gen = new Generator(rng, outfile);

    gen.runTests("P-192", 500);
    gen.runTests("P-224", 500);
    gen.runTests("P-256", 500);
    gen.runTests("P-384", 500);
    gen.runTests("P-521", 500);
  }

  private class Runner implements Runnable {
    private ECDomainParameters params;
    private int count;
    private Generator parent;

    public Runner(ECDomainParameters params, int count, Generator parent)
    {
      this.params = params;
      this.count = count;
      this.parent = parent;
    }

    public void run()
    {
      for(int i = 0; i < count; i++) {
        runTest();
      }
    }

    private AsymmetricCipherKeyPair getKeyPair()
    {
      ECKeyGenerationParameters params =
        new ECKeyGenerationParameters(this.params, this.parent.rng);
      ECKeyPairGenerator keygen = new ECKeyPairGenerator();
      keygen.init(params);
      return keygen.generateKeyPair();
    }

    private byte[] getMessage()
    {
        int msgsize = getRandomChoice(1024);
        byte message[] = new byte[msgsize];
        rng.nextBytes(message);
        return message;
    }

    private byte[] runHash(byte[] msg, int digestsize)
      throws IOException
    {
      Digest digestfn = appropriateDigest(digestsize);
      digestfn.update(msg, 0, msg.length);
      byte result[] = new byte[digestfn.getDigestSize()];
      digestfn.doFinal(result, 0);
      return result;
    }

    private void runTest()
    {
      try {
        AsymmetricCipherKeyPair kp = getKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters)kp.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)kp.getPrivate();

        byte message[] = getMessage();
        int digestsize = randomDigestSize();
        byte hash[] = runHash(message, digestsize);

        Digest msgdigest = appropriateDigest(digestsize);
        HMacDSAKCalculator kgen = new HMacDSAKCalculator(msgdigest);
        ECDSASigner signer = new ECDSASigner(kgen);
        signer.init(true, priv);
        BigInteger rs[] = signer.generateSignature(hash);
        parent.output(kp, digestsize, message, rs);
      } catch(IOException exc) {
        System.out.println("EXCEPTION!");
        run();
      }
    }
  }
}
