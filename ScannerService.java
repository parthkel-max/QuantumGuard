import org.json.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ScannerService {

    static JSONArray rules;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String json = Files.readString(Path.of("data/rules.json"));
            rules = new JSONArray(json);
            System.out.println("Loaded " + rules.length() + " CVE rules.");
        } catch (Exception e) {
            System.out.println("ERROR loading rules.json: " + e.getMessage());
            rules = new JSONArray();
        }
    }

    // ── MAIN SCAN ────────────────────────────────────────────────────
    public static String scan(String requestBody) {
        try {
            JSONObject req  = new JSONObject(requestBody);
            String code     = req.optString("code", "").trim();
            String sector   = req.optString("sector", "other").toLowerCase();

            if (code.isEmpty()) return error("No code provided.");
            if (code.getBytes().length > 51200) return error("Code exceeds 50KB. Paste one file at a time.");

            // Real quantum-safe SHA-3 hash of submitted code
            String sha3Hash = sha3Hash(code);

            // Detect language from first 10 lines
            String language = detectLanguage(code);

            // Split code into individual lines
            String[] lines = code.split("\n");

            // Sector multiplier — healthcare/govt data more sensitive
            double multiplier = getSectorMultiplier(sector);

            JSONArray findings           = new JSONArray();
            int score                    = 100;
            Map<String,Integer> dedCount = new HashMap<>();
            Set<Integer> cryptoLines     = new HashSet<>();

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i].trim();

                // Skip blank lines and comment lines
                if (line.isEmpty() || line.startsWith("//") ||
                    line.startsWith("#") || line.startsWith("*") ||
                    line.startsWith("<!--")) continue;

                for (int j = 0; j < rules.length(); j++) {
                    JSONObject rule    = rules.getJSONObject(j);
                    String ruleLang    = rule.optString("language","universal");

                    // Only apply language-specific rules if language matches
                    if (!ruleLang.equals("universal") && !ruleLang.equals(language)) continue;

                    try {
                        Pattern p = Pattern.compile(rule.getString("pattern"), Pattern.CASE_INSENSITIVE);
                        if (p.matcher(line).find()) {

                            String ruleId  = rule.getString("id");
                            int weight     = rule.getInt("severityWeight");
                            int count      = dedCount.getOrDefault(ruleId, 0);

                            // Cap: same rule deducts at most twice
                            if (count < 2) {
                                score -= (int) Math.ceil(weight * multiplier);
                                dedCount.put(ruleId, count + 1);
                            }

                            if (rule.optString("category","").equals("CRYPTO"))
                                cryptoLines.add(i + 1);

                            JSONObject f = new JSONObject();
                            f.put("lineNumber",    i + 1);
                            f.put("lineContent",   lines[i].trim());
                            f.put("cveId",         rule.getString("cveId"));
                            f.put("name",          rule.getString("name"));
                            f.put("severity",      rule.getString("severity"));
                            f.put("layer",         rule.getString("layer"));
                            f.put("category",      rule.optString("category",""));
                            f.put("presentRisk",   rule.getString("presentRisk"));
                            f.put("quantumImpact", rule.getString("quantumImpact"));
                            f.put("fix",           rule.getString("fix"));
                            f.put("beforeCode",    rule.getString("beforeCode"));
                            f.put("afterCode",     rule.getString("afterCode"));
                            f.put("nistRef",       rule.getString("nistRef"));
                            f.put("fixTimeMinutes",rule.getInt("fixTimeMinutes"));
                            findings.put(f);
                        }
                    } catch (PatternSyntaxException ignored) {}
                }
            }

            score = Math.max(0, score);

            // Migration effort — sum fixTimeMinutes (unique CVEs only)
            int totalMins = 0;
            Set<String> counted = new HashSet<>();
            for (int i = 0; i < findings.length(); i++) {
                String cveId = findings.getJSONObject(i).getString("cveId");
                if (!counted.contains(cveId)) {
                    totalMins += findings.getJSONObject(i).getInt("fixTimeMinutes");
                    counted.add(cveId);
                }
            }

            JSONObject res = new JSONObject();
            res.put("score",          score);
            res.put("grade",          grade(score));
            res.put("agilityScore",   agility(cryptoLines.size(), lines.length));
            res.put("migrationEffort",formatTime(totalMins));
            res.put("language",       language);
            res.put("totalLines",     lines.length);
            res.put("findings",       findings);
            res.put("totalFindings",  findings.length());
            res.put("sha3Hash",       sha3Hash);
            res.put("sector",         sector);
            return res.toString();

        } catch (Exception e) {
            return error("Scan error: " + e.getMessage());
        }
    }

    // ── FORMULA 1: GRADE ─────────────────────────────────────────────
    // 90-100=A  75-89=B  60-74=C  40-59=D  0-39=F
    static String grade(int score) {
        if (score >= 90) return "A";
        if (score >= 75) return "B";
        if (score >= 60) return "C";
        if (score >= 40) return "D";
        return "F";
    }

    // ── FORMULA 2: SECTOR MULTIPLIER ─────────────────────────────────
    static double getSectorMultiplier(String s) {
        return switch (s) {
            case "healthcare"  -> 1.3;
            case "banking"     -> 1.2;
            case "government"  -> 1.3;
            case "education"   -> 1.0;
            default            -> 0.9;
        };
    }

    // ── FORMULA 3: CRYPTO AGILITY ─────────────────────────────────────
    // cryptoLines/totalLines = concentration
    // Lower concentration = higher agility (crypto centralised)
    static int agility(int cryptoLineCount, int totalLines) {
        if (totalLines == 0) return 10;
        double c = (double) cryptoLineCount / totalLines;
        if (c <= 0.02) return 9;
        if (c <= 0.05) return 7;
        if (c <= 0.10) return 5;
        if (c <= 0.20) return 3;
        return 1;
    }

    // ── FORMULA 4: LANGUAGE DETECTION ────────────────────────────────
    // Count keyword matches in first 10 lines per language
    // Highest count wins. Min threshold = 2.
    static String detectLanguage(String code) {
        String[] lines = code.split("\n");
        int limit = Math.min(10, lines.length);
        String sample = String.join("\n", Arrays.copyOfRange(lines, 0, limit)).toLowerCase();

        Map<String, Integer> scores = new LinkedHashMap<>();
        scores.put("java",       score(sample, "import java","public class","system.out","string ","void "));
        scores.put("python",     score(sample, "def ","import ","print(","self.","elif "));
        scores.put("javascript", score(sample, "const ","let ","function ","console.log","require("));
        scores.put("typescript", score(sample, "interface ","type ",": string",": number","import {"));
        scores.put("php",        score(sample, "<?php","echo ","$_post","$_get","mysqli"));
        scores.put("csharp",     score(sample, "using system","namespace ","console.write","static void","class "));
        scores.put("go",         score(sample, "package main","func ","fmt.","import (", ":= "));
        scores.put("ruby",       score(sample, "def ","puts ","require ","end","attr_"));
        scores.put("c",          score(sample, "#include","printf(","int main","scanf(","malloc("));
        scores.put("kotlin",     score(sample, "fun ","val ","var ","println(","data class"));
        scores.put("swift",      score(sample, "import swift","func ","let ","guard ","print("));
        scores.put("rust",       score(sample, "fn main","let mut","println!","use std","impl "));

        String best = "universal";
        int max = 1;
        for (var entry : scores.entrySet()) {
            if (entry.getValue() > max) { max = entry.getValue(); best = entry.getKey(); }
        }
        return best;
    }

    static int score(String text, String... kws) {
        int n = 0;
        for (String k : kws) if (text.contains(k)) n++;
        return n;
    }

    // ── HNDL RISK FORMULA ─────────────────────────────────────────────
    // Score = (DataSensitivity x 0.4) + (QuantumVulnerability x 0.4) + (SectorUrgency x 0.2)
    // Normalised to 0-100
    public static String calculateHNDL(String requestBody) {
        try {
            JSONObject req   = new JSONObject(requestBody);
            String dataType  = req.optString("dataType","other").toLowerCase();
            String sector    = req.optString("sector","other").toLowerCase();
            String algo      = req.optString("worstAlgorithm","none").toLowerCase();

            double ds = switch (dataType) {
                case "health"     -> 10.0;
                case "financial"  -> 9.0;
                case "government" -> 8.0;
                case "personal"   -> 6.0;
                default           -> 3.0;
            };

            double qv = switch (algo) {
                case "rsa"   -> 10.0;
                case "ecc"   -> 9.0;
                case "des"   -> 8.0;
                case "aes128"-> 6.0;
                case "sha1"  -> 5.0;
                case "md5"   -> 4.0;
                default      -> 1.0;
            };

            double su = switch (sector) {
                case "government" -> 10.0;
                case "banking"    -> 10.0;
                case "healthcare" -> 8.0;
                case "education"  -> 5.0;
                default           -> 3.0;
            };

            double raw  = (ds * 0.4) + (qv * 0.4) + (su * 0.2);
            int final_  = (int) Math.round(raw * 10);
            String risk = final_ >= 75 ? "CRITICAL" : final_ >= 50 ? "HIGH" : final_ >= 25 ? "MEDIUM" : "LOW";
            String act  = final_ >= 75
                ? "Immediate migration to CRYSTALS-Kyber and SHA-3 required. Data actively at risk."
                : final_ >= 50 ? "Plan migration within 12 months. India NQM 2027 deadline approaching."
                : final_ >= 25 ? "Schedule migration within 2 years."
                : "Low risk. Review cryptography annually.";

            JSONObject r = new JSONObject();
            r.put("score",     final_);
            r.put("riskLevel", risk);
            r.put("action",    act);
            r.put("formula",   "(" + ds + "×0.4) + (" + qv + "×0.4) + (" + su + "×0.2) = " + String.format("%.1f",raw));
            return r.toString();
        } catch (Exception e) {
            return error("HNDL error: " + e.getMessage());
        }
    }

    // ── SHA-3 — quantum-safe hashing built into JDK 9+ ──────────────
    static String sha3Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] hash = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return "hash-error"; }
    }

    static String formatTime(int m) {
        if (m < 60) return m + " min";
        return (m / 60) + " hr " + (m % 60 > 0 ? (m % 60) + " min" : "");
    }

    static String error(String msg) {
        return "{\"error\":\"" + msg + "\"}";
    }
}
