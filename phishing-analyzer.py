import os
import re
import base64
import argparse
from datetime import datetime, timedelta
from urllib.parse import urlparse
import Levenshtein
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.labels']
KNOWN_BRANDS = ['google', 'paypal', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix', 'bank', 'allegro', 'olx', 'mbank', 'pko', 'ing', 'santander', 'millennium', 'pekao']
SUSPICIOUS_KEYWORDS = ['pilne', 'zablokowane', 'weryfikacja', 'hasło', 'logowanie', 'natychmiast', 'zawieszone', 'konto', 'bezpieczeństwo', 'nieautoryzowany', 'potwierdź', 'aktualizacja', 'faktura', 'płatność']


# Logs into Gmail API, refreshes token if expired
def get_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                print("ERROR: Missing 'credentials.json'. Download it from Google Cloud Console.")
                exit(1)
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            print("Open the link below in your browser in Incognito to log in:")
            creds = flow.run_local_server(port=8080, open_browser=False)
        with open('token.json', 'w') as f:
            f.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)


# Extracts all URLs from HTML and plain-text email body
def extract_urls(html, text):
    urls = set()
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all('a', href=True):
            urls.add(tag['href'])
    if text:
        urls.update(re.findall(r'(https?://[^\s]+)', text))
    return list(urls)


# Returns just the domain from a URL (strips www.)
def get_domain(url):
    try:
        d = urlparse(url).netloc
        if d.startswith('www.'):
            d = d[4:]
        return d
    except:
        return ""


# Checks if a domain is a typosquat of any known brand
def check_typosquatting(domain):
    parts = domain.split('.')
    # Take the part before the last dot, e.g. "gooogle" from "gooogle.com"
    main = parts[-2].lower() if len(parts) >= 2 else domain.lower()
    for brand in KNOWN_BRANDS:
        if main == brand:
            return False, ""
        dist = Levenshtein.distance(main, brand)
        # Distance of 1-2 on a brand longer than 3 chars = suspicious
        if 1 <= dist <= 2 and len(brand) > 3:
            return True, f"Suspicious similarity to brand {brand} (domain: {domain})"
    return False, ""


# Applies the "Phishing" label to a message, creates it first if it doesn't exist
def apply_phishing_label(service, msg_id):
    try:
        all_labels = service.users().labels().list(userId='me').execute().get('labels', [])
        label_id = None
        for l in all_labels:
            if l['name'].lower() == 'phishing':
                label_id = l['id']
                break
        if not label_id:
            # Create the label if it doesn't exist yet
            new_label = {"name": "Phishing", "labelListVisibility": "labelShow", "messageListVisibility": "show"}
            label_id = service.users().labels().create(userId='me', body=new_label).execute()['id']
        service.users().messages().modify(userId='me', id=msg_id, body={'addLabelIds': [label_id]}).execute()
    except Exception as e:
        print(f"Error applying label: {e}")


# Analyzes a single message and returns a report row (or None if no links found)
def analyze_message(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])

    subject = ""
    sender = ""
    sender_domain = ""
    for h in headers:
        if h['name'] == 'Subject':
            subject = h['value']
        if h['name'] == 'From':
            sender = h['value']
            m = re.search(r'@([\w.-]+)', sender)
            if m:
                sender_domain = m.group(1).lower()

    parts = payload.get('parts', []) or [payload]
    html = ""
    text = ""

    # Recursively decodes all message parts (handles nested MIME)
    def decode_part(part):
        nonlocal html, text
        mime = part.get('mimeType')
        data = part.get('body', {}).get('data')
        if data:
            decoded = base64.urlsafe_b64decode(data).decode('utf-8')
            if mime == 'text/html':
                html = decoded
            elif mime == 'text/plain':
                text = decoded
        for sub in part.get('parts', []):
            decode_part(sub)

    for part in parts:
        decode_part(part)

    urls = extract_urls(html, text)
    if not urls:
        return None

    score = 0
    reasons = []

    full_text = (subject + " " + text + " " + html).lower()
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    if found_kw:
        score += 3
        reasons.append(f"Suspicious keywords: {', '.join(found_kw)}")

    for url in urls:
        link_domain = get_domain(url).lower()
        if not link_domain:
            continue
        # Link domain differs from sender domain — suspicious
        if sender_domain and sender_domain not in link_domain and link_domain not in sender_domain:
            score += 5
            reasons.append(f"Domain mismatch: sender ({sender_domain}) vs link ({link_domain})")
        is_typo, typo_msg = check_typosquatting(link_domain)
        if is_typo:
            score += 8
            reasons.append(typo_msg)

    reasons = list(set(reasons))
    is_phishing = score >= 8

    if is_phishing:
        apply_phishing_label(service, msg_id)

    links_str = "<br>".join(urls[:3])
    if len(urls) > 3:
        links_str += f"<br>...and {len(urls) - 3} more"

    just_str = "<br>".join(reasons) if reasons else "No issues"
    display_subject = f"**[PHISHING]** {subject}" if is_phishing else subject
    risk_label = "High" if is_phishing else ("Medium" if score > 0 else "Low")

    return f"| {sender} | {display_subject} | {links_str} | {risk_label} ({score}) | {just_str} |"


parser = argparse.ArgumentParser(description='Phishing Analyzer for Gmail')
parser.add_argument('--hours', type=int, default=0, help='Analyze emails from the last X hours')
parser.add_argument('--count', type=int, default=15, help='Analyze the last X emails (if hours not provided)')
args = parser.parse_args()

print("Connecting to Gmail API...")
service = get_service()

query = ""
if args.hours > 0:
    past_time = int((datetime.now() - timedelta(hours=args.hours)).timestamp())
    query = f"after:{past_time}"
    print(f"Fetching emails from the last {args.hours} hours...")
else:
    print(f"Fetching the last {args.count} emails...")

max_results = args.count if args.hours == 0 else 100
messages = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute().get('messages', [])

if not messages:
    print("No messages found.")
else:
    report = [f"# Phishing Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
              "| Sender | Subject | Links | Risk | Reasons |",
              "|---|---|---|---|---|"]
    found_phishing = False

    for msg in messages:
        row = analyze_message(service, msg['id'])
        if row:
            report.append(row)
            if "**[PHISHING]**" in row:
                found_phishing = True

    if len(report) == 3:
        report.append("| None | None | No messages with links | N/A | N/A |")

    os.makedirs('reports', exist_ok=True)
    filename = f"reports/phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(report))

    print(f"\nDone. Report saved to: {filename}")
    if found_phishing:
        print("\n!!! WARNING: Potential phishing emails detected (marked [PHISHING]). Do not click any links! !!!")
