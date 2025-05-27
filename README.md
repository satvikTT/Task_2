# EMAIL PHISHING AND ANALYSIS PROJECT (TASK-2)

Learn how to discover that the email is spoofed and to get protetected by it to deepen your understanding of network behavior and improve security changes.

---

## Objective

Identify phishing characteristics in a suspicious email sample using manual analysis and online tools.

---

## Tools Required

- Email client or saved email file (text format preferred: `.eml`, `.txt`)
- Free online header analyzer (e.g., [MxToolbox](https://mxtoolbox.com/EmailHeaders.aspx), [Google Admin Toolbox](https://toolbox.googleapps.com/apps/messageheader/))

---

## Files Included

- **test.py**  
A Python script that processes a raw email, extracts key headers, identifies suspicious URLs, scans the email body for urgency cues and grammatical issues, and produces a phishing detection report.

- **phishing_email.txt**  
A sample phishing email text file utilized as input for the analysis script.

- **report.txt**  
A structured report highlighting the phishing indicators detected in the sample email.
---

## Procedure

### 1. Examine Sender’s Email
- Check the “From” address for spoofed domains.
- Look for discrepancies like suspicious domain names (e.g., `micr0soft.com`).

### 2. Analyze Email Headers
- Extract headers from your email client.
- Use an online header analyzer to identify:
  - IP mismatches
  - SPF, DKIM, or DMARC failures
  - Relay inconsistencies

### 3. Place the `phishing_email.txt` and `test.py` files in the same folder.
### Run the script with:

   ```bash
   python test.py
   ```
### 6. For creating a report file in the same folder , run the script with :
   
   ```bash
   python test.py > report.txt
   ```

