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
  Python script that parses the raw email, extracts headers, checks for suspicious links, analyzes the email body for urgent language and grammar errors, and generates a phishing analysis report.

- **phishing_email.txt**  
  Sample phishing email text file used as input to the analysis script.

- **report.txt**  
  A formatted report summarizing the phishing characteristics found in the sample email.

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

