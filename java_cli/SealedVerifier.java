import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * SEALED Enterprise Java Evidence Pack Verifier (Zero External Dependencies).
 *
 * Validates:
 *   1. Zip-Slip traversal protection (rejects absolute paths and '..' segments)
 *   2. Decompression bomb protection (100 MB cap, 1000 entry cap)
 *   3. Cryptographic SHA-256 hash chain continuity across every block
 *   4. Final chain hash equality with manifest.json
 *
 * Compile: javac java_cli/SealedVerifier.java
 * Run:     java -cp java_cli SealedVerifier evidence.zip
 */
public final class SealedVerifier {
    private static final int MAX_ENTRIES = 1000;
    private static final long MAX_TOTAL_BYTES = 100L * 1024L * 1024L;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -cp java_cli SealedVerifier <evidence.zip>");
            System.exit(2);
        }

        Path zipPath = Paths.get(args[0]);
        if (!Files.isRegularFile(zipPath)) {
            System.err.println("[FAIL] Evidence archive not found: " + zipPath);
            System.exit(2);
        }

        try {
            Map<String, String> entries = readArchiveSafely(zipPath);
            if (!entries.containsKey("chain.json") || !entries.containsKey("manifest.json")) {
                throw new SecurityException("Archive missing required chain.json or manifest.json");
            }

            String manifestJson = entries.get("manifest.json");
            String chainJson = entries.get("chain.json");

            String expectedFinalHash = extractField(manifestJson, "final_chain_hash");
            List<Map<String, String>> blocks = parseChainBlocks(chainJson);

            for (int i = 0; i < blocks.size(); i++) {
                Map<String, String> block = blocks.get(i);
                String prevHash = block.get("prev_hash");
                String blockHash = block.get("block_hash");
                String findingId = block.get("finding_id");
                String payloadSha = block.get("payload_sha256");

                if (i > 0) {
                    String priorHash = blocks.get(i - 1).get("block_hash");
                    if (!prevHash.equals(priorHash)) {
                        throw new SecurityException("Hash chain link broken at block #" + i);
                    }
                }

                String recomputed = sha256Hex(prevHash + ":" + findingId + ":" + payloadSha);
                if (!recomputed.equals(blockHash)) {
                    throw new SecurityException(
                        "Cryptographic tamper detected at block #" + i
                            + " (expected " + recomputed + ", found " + blockHash + ")"
                    );
                }
            }

            if (!blocks.isEmpty()) {
                String actualFinal = blocks.get(blocks.size() - 1).get("block_hash");
                if (!actualFinal.equals(expectedFinalHash)) {
                    throw new SecurityException("Final chain hash does not match manifest.json");
                }
            }

            System.out.println("[OK] Java SealedVerifier: " + blocks.size() + " blocks cryptographically verified.");
            System.out.println("     Final Chain Hash: " + expectedFinalHash);
            System.exit(0);
        } catch (Exception ex) {
            System.err.println("[FAIL] Verification failed: " + ex.getMessage());
            System.exit(2);
        }
    }

    private static Map<String, String> readArchiveSafely(Path zipPath) throws IOException {
        Map<String, String> result = new HashMap<>();
        long totalBytes = 0;
        int entryCount = 0;

        try (ZipFile zipFile = new ZipFile(zipPath.toFile())) {
            Enumeration<? extends ZipEntry> enumeration = zipFile.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                entryCount++;
                if (entryCount > MAX_ENTRIES) {
                    throw new SecurityException("Archive entry count exceeded limit of " + MAX_ENTRIES);
                }

                String name = entry.getName();
                if (name.startsWith("/") || name.startsWith("\\") || name.matches("^[A-Za-z]:.*")) {
                    throw new SecurityException("Zip-Slip blocked: absolute path entry '" + name + "'");
                }
                for (String segment : name.split("[/\\\\]")) {
                    if ("..".equals(segment)) {
                        throw new SecurityException("Zip-Slip blocked: traversal segment in '" + name + "'");
                    }
                }

                if (entry.isDirectory()) {
                    continue;
                }

                try (InputStream is = zipFile.getInputStream(entry);
                     ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[8192];
                    int read;
                    while ((read = is.read(buf)) != -1) {
                        totalBytes += read;
                        if (totalBytes > MAX_TOTAL_BYTES) {
                            throw new SecurityException("Decompression bomb blocked: exceeded 100MB limit");
                        }
                        baos.write(buf, 0, read);
                    }
                    result.put(name, baos.toString(StandardCharsets.UTF_8.name()));
                }
            }
        }
        return result;
    }

    private static List<Map<String, String>> parseChainBlocks(String chainJson) {
        List<Map<String, String>> blocks = new ArrayList<>();
        Pattern objPattern = Pattern.compile("\\{[^{}]*\\}");
        Matcher matcher = objPattern.matcher(chainJson);
        while (matcher.find()) {
            String obj = matcher.group();
            Map<String, String> map = new HashMap<>();
            map.put("prev_hash", extractField(obj, "prev_hash"));
            map.put("block_hash", extractField(obj, "block_hash"));
            map.put("finding_id", extractField(obj, "finding_id"));
            map.put("payload_sha256", extractField(obj, "payload_sha256"));
            blocks.add(map);
        }
        return blocks;
    }

    private static String extractField(String json, String fieldName) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) {
            throw new IllegalArgumentException("Missing required JSON field: " + fieldName);
        }
        return m.group(1);
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
