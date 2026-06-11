# 🛡️ Gmail Phishing Analyzer

A fully automated Python script for monitoring and analyzing Gmail email messages for advanced phishing attacks.

The script uses the Gmail API to fetch emails and then subjects them to multi-stage verification. If the algorithm identifies a message as a phishing attempt, it automatically flags it in your mailbox as suspicious.

## 🚀 How does it work?

When the script retrieves a new message, it analyzes it for the following threats:
1. **Contextual Analysis:** Detects keywords that create time pressure or fear (e.g., "account locked", "urgent", "verification", "immediately").
2. **Sender Domain Verification:** Compares the original domain from which the email was sent (e.g., `paypal-support@scam.com`) with the legitimate URLs embedded in buttons (e.g., click here → paypal.com). If there's a mismatch, it's flagged.
3. **Typosquatting:** The script calculates [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance) for extracted links against known brands (e.g., it will detect if you receive an email from "gogle.com" instead of "google.com").

## 🛠️ Requirements

- Installed **Python 3.x**
- A Google account (Gmail)

## 📦 Installation

1. Clone this repository to your disk:
   ```bash
   git clone https://github.com/matiziompl/phishing-analyzer.git
   cd phishing-analyzer
   ```
2. Install the required Python libraries:
   ```bash
   python -m pip install -r requirements.txt
   ```

## 🔑 Configuration (Google Cloud Console)

For the script to safely read your mailbox without entering a password, you must create your own `credentials.json` file using the OAuth 2.0 protocol. This is a standard procedure enforced by Google.

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project and navigate to **APIs & Services > Library**.
3. Search for and enable (**Enable**) the **Gmail API** service.
4. On the **OAuth consent screen** tab, select type **External**, fill in the name, and save. **Important:** At the bottom in the **Test users** section, add your personal email address that you'll use to log in.
5. Go to the **Credentials** tab, click **Create Credentials** → **OAuth client ID**.
6. Select type: **Desktop app**.
7. Download the JSON file with your key, rename it exactly to `credentials.json`, and upload it to the main folder of this script.

## 🏃 Manual Execution

To download and analyze the last 15 messages, run:
```bash
python phishing-analyzer.py --count 15
```

On the first run, a browser window will open asking you to log in with your Gmail account. After confirming permissions, a new `token.json` file will appear next to the script, and the system will generate a report.

## ⚙️ Windows Task Scheduler (Daily at 9:00 AM)

The script is prepared to work in the background. Run Windows PowerShell **as administrator** in the project folder and type:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_schedule.ps1
```

The task will automatically be saved in your Windows Task Scheduler. From now on, your computer will daily download emails from the last 24 hours, filter them, and flag suspicious ones.

---
*⚠️ Disclaimer: This project is a supporting tool based on heuristics. No automation provides 100% certainty, so always use common sense and be vigilant when clicking links in emails.*
