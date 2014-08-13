package org.meri.matasano.utils.cryptoanalysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.meri.matasano.utils.ArrayManips;
import org.meri.matasano.utils.RandomUtils;
import org.meri.matasano.utils.encryption.RSA.RSAPublicKey;
import org.meri.matasano.utils.oracle.PaddingRSAOracle;

// based on http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf
public class Bleichenbacher98 implements IBleichenbacher98 {
  private static final BigInteger ZERO = BigInteger.ZERO;
  private static final BigInteger ONE = BigInteger.ONE;
  private static final BigInteger MinusONE = BigInteger.ONE.negate();
  private static final BigInteger TWO = BigInteger.valueOf(2);
  private static final BigInteger THREE = BigInteger.valueOf(3);

  private final RandomUtils random = new RandomUtils();
  private final ArrayManips manips = new ArrayManips();

  private PaddingRSAOracle oracle;
  private List<BigInteger> s = new ArrayList<BigInteger>();
  private BigInteger c0;
  private BigInteger ciphertext;
  private RSAPublicKey publicKey;
  private BigInteger e;
  private BigInteger n;
  private BigInteger B;
  private BigInteger B2;
  private BigInteger B3;
  private int i;
  private Set<Interval> intervals;
  private boolean hadMultiple = false;

  public boolean hadMultiple() {
    return hadMultiple;
  }

  public void setHadMultiple(boolean hadMultiple) {
    this.hadMultiple = hadMultiple;
  }

  public byte[] decryptRSAPaddingOracle(byte[] ciphertext, PaddingRSAOracle oracle) {
    initState(ciphertext, oracle);
    step1Blinding();
    while (!singleSmallInterval()) {
      step2Search();
      step3Narrow();
      i++;
    }
    System.out.println("Yabba dabba doo!");

    return step4ComputeTheSolution();
  }

  private boolean singleSmallInterval() {
    if (intervals.size() != 1)
      return false;

    return getOneInterval().hasRangeOne();
  }

  private Interval getOneInterval() {
    return intervals.iterator().next();
  }

  private byte[] step4ComputeTheSolution() {
    BigInteger s0Inverse = s0().modInverse(n);
    BigInteger almostThere = getOneInterval().getA().multiply(s0Inverse).mod(n);

    return manips.join(new byte[] { 0 }, almostThere.toByteArray());
  }

  private void step3Narrow() {
    Set<Interval> result = new HashSet<Interval>();
    for (Interval interval : intervals) {
      result.addAll(deriveNextIntervals(interval));
    }
    intervals = result;
    System.out.println("narrowed to intervals: " + intervals.size() + " diffenrence in one: " + getOneInterval().getRange());
  }

  private Set<Interval> deriveNextIntervals(Interval interval) {
    BigInteger a = interval.getA();
    BigInteger b = interval.getB();

    Set<Interval> result = new HashSet<Interval>();
    BigInteger si = si();
    BigInteger minusB3PlusOne = B3.negate().add(ONE);
    BigInteger asi = a.multiply(si);
    BigInteger nominator = asi.add(minusB3PlusOne);
    BigInteger newRMinimum = divideRoundUp(nominator, n);

    BigInteger bsi = b.multiply(si);
    BigInteger newRMaximum = bsi.add(B2.negate()).divide(n);
    assertMinMax(newRMinimum, newRMaximum);

    BigInteger r = newRMinimum;
    while (r.compareTo(newRMaximum) <= 0) {
      BigInteger rn = r.multiply(n);
      BigInteger otherMinimum = divideRoundUp(B2.add(rn), si);

      result.add(new Interval(a.max(otherMinimum), b.min(B3.add(MinusONE).add(rn).divide(si))));

      r = r.add(ONE);
    }

    return result;
  }

  private void step2Search() {
    if (i == 1) {
      step2AStartTheSearch();
    } else {
      if (intervals.size() == 1)
        step2COneIntervalLeft();
      else
        step2MultipleIntervals();
    }
  }

  private void step2MultipleIntervals() {
    hadMultiple = true;
    System.out.println("Using multiple - begin.");
    
    BigInteger siCandidate = sim1().add(ONE);
    while (!oracle.hasValidPadding(multiplyEncryptedPlaintext(c0, siCandidate))) {
      siCandidate = siCandidate.add(ONE);
    }
    addS(siCandidate);
    System.out.println("Using multiple - end.");
  }

  private void step2COneIntervalLeft() {
    BigInteger a = getOneInterval().getA();
    BigInteger b = getOneInterval().getB();

    BigInteger bsim1 = b.multiply(sim1());
    BigInteger minus2B = B2.negate();
    BigInteger lowerRiBound = divideRoundUp(TWO.multiply(bsim1.add(minus2B)), n);
    assertPositive(lowerRiBound);

    BigInteger ri = lowerRiBound.add(MinusONE);
    BigInteger si = null;
    while (si == null) {
      ri = ri.add(ONE);
      BigInteger rin = ri.multiply(n);
      BigInteger siCandidate = divideRoundUp(B2.add(rin), b);
      BigInteger outOfReach = B3.add(rin).divide(a).add(ONE);

      BigInteger modifiedCiper = multiplyEncryptedPlaintext(c0, siCandidate);
      while (!oracle.hasValidPadding(modifiedCiper) && !siCandidate.equals(outOfReach)) {
        siCandidate = siCandidate.add(ONE);
        modifiedCiper = multiplyEncryptedPlaintext(c0, siCandidate);
      }
      if (!siCandidate.equals(outOfReach)) {
        si = siCandidate;
      }
    }
    addS(si);
  }

  private BigInteger divideRoundUp(BigInteger up, BigInteger down) {
    BigInteger remainder = up.mod(down).equals(ZERO) ? ZERO : ONE;
    BigInteger div = up.divide(down);
    return div.add(remainder);
  }

  private void addS(BigInteger si) {
    assertPositive(si);

    s.add(si);
  }

  private BigInteger sim1() {
    return s.get(i - 1);
  }

  private BigInteger si() {
    return s.get(i);
  }

  private BigInteger s0() {
    return s.get(0);
  }

  private void step2AStartTheSearch() {
    System.out.println("Search Start");
    BigInteger s1 = divideRoundUp(n, B3);

    BigInteger encryptedCombination = multiplyEncryptedPlaintext(c0, s1);
    while (!oracle.hasValidPadding(encryptedCombination)) {
      s1 = s1.add(ONE);
      encryptedCombination = multiplyEncryptedPlaintext(c0, s1);

      System.out.println("Search a: " + s1);
    }

    addS(s1);
    System.out.println("Search End");
  }

  private void step1Blinding() {
    System.out.println("Blinding Start");
    BigInteger s0 = ONE;
    BigInteger blind = multiplyEncryptedPlaintext(s0);
    int attempt = 0;
    while (!oracle.hasValidPadding(blind)) {
      attempt++;
      s0 = random.getPositiveBigInteger(n);
      blind = multiplyEncryptedPlaintext(s0);

      System.out.println("Blinding " + (65025 - attempt) + ": " + s0);
    }
    addS(s0);
    c0 = blind;

    addInterval(B2, B3.add(MinusONE));
    i = 1;
    System.out.println("Blinding End");
  }

  private void addInterval(BigInteger a, BigInteger b) {
    this.intervals.add(new Interval(a, b));
  }

  private BigInteger multiplyEncryptedPlaintext(BigInteger modification) {
    return multiplyEncryptedPlaintext(ciphertext, modification);
  }

  private BigInteger multiplyEncryptedPlaintext(BigInteger ciphertext, BigInteger modification) {
    return ciphertext.multiply(modification.modPow(e, n)).mod(n);
  }

  private void initState(byte[] ciphertext, PaddingRSAOracle oracle) {
    intervals = new HashSet<Interval>();
    this.oracle = oracle;
    this.ciphertext = new BigInteger(ciphertext);
    publicKey = oracle.getPublicKey();
    e = publicKey.getE();
    n = publicKey.getN();
    int k = n.toByteArray().length;
    B = TWO.pow(8 * (k - 2));
    B2 = TWO.multiply(B);
    B3 = THREE.multiply(B);
    s = new ArrayList<BigInteger>();
  }

  private void assertPositive(BigInteger number) {
    if (number.compareTo(ZERO) < 0) {
      System.out.println("negative");
    }
  }

  private void assertMinMax(BigInteger min, BigInteger max) {
    if (max.compareTo(min) < 0) {
      System.out.println("ddd");
      System.out.println("ddd");
    }
  }

}

class Interval {

  private final BigInteger a;
  private final BigInteger b;

  public Interval(BigInteger a, BigInteger b) {
    super();
    this.a = a;
    this.b = b;
  }

  public BigInteger getRange() {
    return b.add(a.negate());
  }

  public BigInteger getA() {
    return a;
  }

  public BigInteger getB() {
    return b;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((a == null) ? 0 : a.hashCode());
    result = prime * result + ((b == null) ? 0 : b.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    Interval other = (Interval) obj;
    if (a == null) {
      if (other.a != null)
        return false;
    } else if (!a.equals(other.a))
      return false;
    if (b == null) {
      if (other.b != null)
        return false;
    } else if (!b.equals(other.b))
      return false;
    return true;
  }

  public boolean hasRangeOne() {
    return a.equals(b);
  }
  
  
}
