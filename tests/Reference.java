import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import java.io.File;
import java.security.MessageDigest;
import java.util.HexFormat;
public class Reference {
 static String fingerprint(java.security.cert.X509Certificate cert) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())); }
 static boolean hybrid(ApkVerifier.Result r) { try { return (boolean) r.getClass().getMethod("isVerifiedUsingV32Scheme").invoke(r); } catch (NoSuchMethodException e) { return false; } catch (Exception e) { throw new RuntimeException(e); } }
 public static void main(String[] args) throws Exception {
  if (args[0].equals("lineage")) {
   SigningCertificateLineage lineage = SigningCertificateLineage.readFromFile(new File(args[1]));
   int count = lineage.getCertificatesInLineage().size();
   System.out.println("lineage certificates=" + count);
   if (args.length > 2 && count != Integer.parseInt(args[2])) throw new AssertionError("Unexpected lineage length");
   return;
  }
  int sdk = Integer.parseInt(args[2]);
  ApkVerifier.Result result = new ApkVerifier.Builder(new File(args[1])).setMinCheckedPlatformVersion(sdk).setMaxCheckedPlatformVersion(sdk).build().verify();
  System.out.println("verified="+result.isVerified()+" v2="+result.isVerifiedUsingV2Scheme()+" v3="+result.isVerifiedUsingV3Scheme()+" v31="+result.isVerifiedUsingV31Scheme()+" v32="+hybrid(result));
  if (!result.isVerified()) {System.err.println(result.getAllErrors()); System.exit(1);}
  for (var cert : result.getSignerCertificates()) System.out.println("signer_sha256=" + fingerprint(cert));
  if (args.length > 3 && (result.getSignerCertificates().size() != 1 || !fingerprint(result.getSignerCertificates().get(0)).equals(args[3]))) throw new AssertionError("Unexpected selected signer");
 }
}
