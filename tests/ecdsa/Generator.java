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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
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
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

class Generator {
  final static int COUNT = 500;

  public static void main(String[] args)
    throws IOException, InterruptedException
  {
    new Generator().run();
  }

  public Generator() { }

  public void run()
    throws IOException, InterruptedException
  {
    OutFiles outfiles = new OutFiles();
    String[] curves = { "P-192", "P-224", "P-256", "P-384", "P-521" };
    ArrayList<Thread> threads = new ArrayList<Thread>();

    System.out.print("Generating: ");
    for(String curve : curves) {
      X9ECParameters params = NISTNamedCurves.getByName(curve);
      ECDomainParameters dp = new ECDomainParameters(params.getCurve(),
                                                     params.getG(),
                                                     params.getN());
      Runner runner = new Runner(outfiles, dp);
      Thread thread = new Thread(runner);
      thread.start();
      threads.add(thread);
    }

    for(Thread thread: threads) {
      thread.join();
    }
    System.out.println(" done.");
  }

  public class OutFiles {
    public FileWriter negate;
    public FileWriter dble;
    public FileWriter add;
    public FileWriter mul;
    public FileWriter add2mul;
    public FileWriter sig;

    public OutFiles()
    {
      try {
        negate  = new FileWriter("ec_negate.test",  false);
        dble    = new FileWriter("ec_dble.test",    false);
        add     = new FileWriter("ec_add.test",     false);
        mul     = new FileWriter("ec_mul.test",     false);
        add2mul = new FileWriter("ec_add2mul.test", false);
        sig     = new FileWriter("signature.test",  false);
      } catch(IOException e) {
        System.out.println("Blech: " + e);
      }
    }

    public synchronized void dump(FileWriter file, Map<String,String> x) {
      try {
        for(Map.Entry<String,String> entry : x.entrySet()) {
          file.write(entry.getKey());
          file.write(": ");
          file.write(entry.getValue());
          file.write("\n");
          file.flush();

          if(file == negate)  { System.out.print("N"); };
          if(file == dble)    { System.out.print("D"); };
          if(file == add)     { System.out.print("A"); };
          if(file == mul)     { System.out.print("M"); };
          if(file == add2mul) { System.out.print("2"); };
          if(file == sig)     { System.out.print("S"); };
          System.out.flush();
        }
      } catch(IOException e) {
        System.out.println("Argh: " + e);
      }
    }
  }

  public class Runner implements Runnable {
    private OutFiles outfiles;
    private SecureRandom rng;
    private ECDomainParameters ecparams;
    private BigInteger two;

    public Runner(OutFiles outfiles, ECDomainParameters params) {
      this.outfiles = outfiles;
      this.ecparams = params;
      this.rng = new SecureRandom();
      this.two = BigInteger.valueOf(2);
    }

    public void run() {
      for(int i = 0; i < COUNT; i++) { generateNegateTests(); }
      for(int i = 0; i < COUNT; i++) { generateDoubleTests(); }
      for(int i = 0; i < COUNT; i++) { generateAddTests(); }
      for(int i = 0; i < COUNT; i++) { generateMulTests(); }
      for(int i = 0; i < COUNT; i++) { generateAdd2MulTests(); }
      for(int i = 0; i < COUNT; i++) { generateSignatureTests(); }
    }

    public void generateNegateTests() {
      ECPoint p = getPoint();
      ECPoint n = p.negate().normalize();
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", p.getAffineXCoord().toBigInteger().toString(16));
      m.put("y", p.getAffineYCoord().toBigInteger().toString(16));
      m.put("a", n.getAffineXCoord().toBigInteger().toString(16));
      m.put("b", n.getAffineYCoord().toBigInteger().toString(16));
      outfiles.dump(outfiles.negate, m);
    }

    public void generateDoubleTests() {
      ECPoint p = getPoint();
      ECPoint n = p.twice().normalize();
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", p.getAffineXCoord().toBigInteger().toString(16));
      m.put("y", p.getAffineYCoord().toBigInteger().toString(16));
      m.put("a", n.getAffineXCoord().toBigInteger().toString(16));
      m.put("b", n.getAffineYCoord().toBigInteger().toString(16));
      outfiles.dump(outfiles.dble, m);
    }

    public void generateAddTests() {
      ECPoint p1 = getPoint();
      ECPoint p2 = getPoint();
      ECPoint q  = p1.add(p2).normalize();
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", p1.getAffineXCoord().toBigInteger().toString(16));
      m.put("y", p1.getAffineYCoord().toBigInteger().toString(16));
      m.put("q", p2.getAffineXCoord().toBigInteger().toString(16));
      m.put("r", p2.getAffineYCoord().toBigInteger().toString(16));
      m.put("a", q.getAffineXCoord().toBigInteger().toString(16));
      m.put("b", q.getAffineYCoord().toBigInteger().toString(16));
      outfiles.dump(outfiles.add, m);
    }

    public void generateMulTests() {
      ECPoint p = getPoint();
      BigInteger k = getConstant();
      ECPoint q = p.multiply(k).normalize();
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", p.getAffineXCoord().toBigInteger().toString(16));
      m.put("y", p.getAffineYCoord().toBigInteger().toString(16));
      m.put("k", k.toString(16));
      m.put("a", q.getAffineXCoord().toBigInteger().toString(16));
      m.put("b", q.getAffineYCoord().toBigInteger().toString(16));
      outfiles.dump(outfiles.mul, m);
    }

    public void generateAdd2MulTests() {
      ECPoint p = getPoint();
      BigInteger a = getConstant();
      ECPoint q = getPoint();
      BigInteger b = getConstant();
      ECPoint r = ECAlgorithms.sumOfTwoMultiplies(p,a,q,b).normalize();
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", p.getAffineXCoord().toBigInteger().toString(16));
      m.put("y", p.getAffineYCoord().toBigInteger().toString(16));
      m.put("a", a.toString(16));
      m.put("q", q.getAffineXCoord().toBigInteger().toString(16));
      m.put("r", q.getAffineYCoord().toBigInteger().toString(16));
      m.put("b", b.toString(16));
      m.put("s", r.getAffineXCoord().toBigInteger().toString(16));
      m.put("t", r.getAffineYCoord().toBigInteger().toString(16));
      outfiles.dump(outfiles.add2mul, m);
    }

    public void generateSignatureTests() {
      AsymmetricCipherKeyPair kp = getKeyPair();
      ECPublicKeyParameters pub = (ECPublicKeyParameters)kp.getPublic();
      ECPrivateKeyParameters priv = (ECPrivateKeyParameters)kp.getPrivate();
      byte message[] = getMessage();
      int digestsize = getDigestSize();
      byte hash[] = runHash(message, digestsize);
      Digest msgdigest = getHash(digestsize);
      HMacDSAKCalculator kgen = new HMacDSAKCalculator(msgdigest);
      ECDSASigner signer = new ECDSASigner(kgen);
      signer.init(true, priv);
      BigInteger rs[] = signer.generateSignature(hash);
      HashMap<String,String> m = new HashMap<String,String>();

      m.put("c", Integer.toString(ecparams.getN().bitLength()));
      m.put("x", pub.getQ().getAffineXCoord().toBigInteger().toString(16));
      m.put("y", pub.getQ().getAffineYCoord().toBigInteger().toString(16));
      m.put("d", priv.getD().toString(16));
      m.put("h", Integer.toString(digestsize));
      m.put("m", asHex(message));
      m.put("r", rs[0].toString(16));
      m.put("s", rs[1].toString(16));
      outfiles.dump(outfiles.sig, m);
    }

    private byte[] runHash(byte[] msg, int size) {
      Digest digestfn = getHash(size);
      digestfn.update(msg, 0, msg.length);
      byte result[] = new byte[digestfn.getDigestSize()];
      digestfn.doFinal(result, 0);
      return result;
    }

    private AsymmetricCipherKeyPair getKeyPair() {
      ECKeyGenerationParameters params =
        new ECKeyGenerationParameters(ecparams, rng);
      ECKeyPairGenerator keygen = new ECKeyPairGenerator();
      keygen.init(params);
      return keygen.generateKeyPair();
    }

    private byte[] getMessage() {
      int msgsize = rng.nextInt(1024);
      byte message[] = new byte[msgsize];
      rng.nextBytes(message);
      return message;
    }

    private ECPoint getPoint() {
      BigInteger k = getConstant();
      return ecparams.getG().multiply(k).normalize();
    }

    private BigInteger getConstant() {
      BigInteger n = ecparams.getN();
      int nBitLength = n.bitLength();

      for(;;) {
        BigInteger d = new BigInteger(nBitLength, rng);

        if(d.compareTo(two) < 0 || (d.compareTo(n) >= 0)) {
          continue;
        }

        return d;
      }
    }

    private int getDigestSize() {
      switch(rng.nextInt(5)) {
        case 0: return 1;
        case 1: return 224;
        case 2: return 256;
        case 3: return 384;
        case 4: return 512;
        default:
          return 999;
      }
    }

    private Digest getHash(int nsize) {
      switch(nsize) {
        case 1:   return new SHA1Digest();
        case 224: return new SHA1Digest();
        case 256: return new SHA1Digest();
        case 384: return new SHA1Digest();
        case 512: return new SHA1Digest();
        default:
          return null;
      }
    }

    private String asHex(byte[] data) {
      String result = "";
      for(byte value : data) {
        result = result + String.format("%02x", value);
      }
      return result;
    }
 }

}
