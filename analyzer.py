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

def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                print("BŁĄD: Brak pliku 'credentials.json'. Pobierz go z Google Cloud Console dla swojego projektu.")
                exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            print("Otwórz poniższy link w przeglądarce (najlepiej w trybie Incognito), aby się zalogować:")
            creds = flow.run_local_server(port=0, open_browser=False)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def extract_urls(html_content, text_content):
    urls = set()
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        for a_tag in soup.find_all('a', href=True):
            urls.add(a_tag['href'])
    
    if text_content:
        raw_urls = re.findall(r'(https?://[^\s]+)', text_content)
        urls.update(raw_urls)
        
    return list(urls)

def get_domain(url):
    try:
        parsed_uri = urlparse(url)
        domain = '{uri.netloc}'.format(uri=parsed_uri)
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return ""

def check_typosquatting(domain):
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        main_part = domain_parts[-2].lower()
    else:
        main_part = domain.lower()
        
    for brand in KNOWN_BRANDS:
        if main_part == brand:
            return False, ""
        dist = Levenshtein.distance(main_part, brand)
        if 1 <= dist <= 2 and len(brand) > 3:
            return True, f"Podejrzane podobieństwo do marki {brand} (domena: {domain})"
    
    return False, ""

def analyze_message(service, msg_id):
    message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = message.get('payload', {})
    headers = payload.get('headers', [])
    
    subject = ""
    sender = ""
    sender_domain = ""
    
    for header in headers:
        if header['name'] == 'Subject':
            subject = header['value']
        if header['name'] == 'From':
            sender = header['value']
            match = re.search(r'@([\w.-]+)', sender)
            if match:
                sender_domain = match.group(1).lower()

    parts = payload.get('parts', [])
    html_content = ""
    text_content = ""
    
    if not parts:
        parts = [payload]

    def decode_part(part):
        nonlocal html_content, text_content
        mimeType = part.get('mimeType')
        body = part.get('body', {})
        data = body.get('data')
        if data:
            decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
            if mimeType == 'text/html':
                html_content = decoded_data
            elif mimeType == 'text/plain':
                text_content = decoded_data
        
        if part.get('parts'):
            for subpart in part['parts']:
                decode_part(subpart)

    for part in parts:
        decode_part(part)

    urls = extract_urls(html_content, text_content)
    
    if not urls:
        return None

    risk_score = 0
    justification = []
    
    full_text = (subject + " " + text_content + " " + html_content).lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    if found_keywords:
        risk_score += 3
        justification.append(f"Podejrzane słowa kluczowe: {', '.join(found_keywords)}")

    for url in urls:
        link_domain = get_domain(url).lower()
        if not link_domain:
            continue
            
        if sender_domain and link_domain and sender_domain not in link_domain and link_domain not in sender_domain:
            risk_score += 5
            justification.append(f"Rozbieżność domen: nadawca ({sender_domain}) vs link ({link_domain})")
            
        is_typo, typo_msg = check_typosquatting(link_domain)
        if is_typo:
            risk_score += 8
            justification.append(typo_msg)

    justification = list(set(justification))
    is_phishing = risk_score >= 8
    
    if is_phishing:
        try:
            results = service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            phishing_label_id = None
            for label in labels:
                if label['name'].lower() == 'phishing':
                    phishing_label_id = label['id']
                    break
            
            if not phishing_label_id:
                label_object = {
                    "name": "Phishing",
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show"
                }
                created_label = service.users().labels().create(userId='me', body=label_object).execute()
                phishing_label_id = created_label['id']

            service.users().messages().modify(
                userId='me', 
                id=msg_id, 
                body={'addLabelIds': [phishing_label_id]}
            ).execute()
        except Exception as e:
            print(f"Błąd podczas nadawania etykiety: {e}")

    links_str = "<br>".join(urls[:3])
    if len(urls) > 3:
        links_str += f"<br>...i {len(urls)-3} więcej"
        
    just_str = "<br>".join(justification) if justification else "Brak uwag"
    
    display_subject = subject
    if is_phishing:
        display_subject = f"**[PHISHING]** {subject}"

    risk_label = "Wysokie" if is_phishing else ("Średnie" if risk_score > 0 else "Niskie")
    
    return f"| {sender} | {display_subject} | {links_str} | {risk_label} ({risk_score}) | {just_str} |"

def main():
    parser = argparse.ArgumentParser(description='Phishing Analyzer for Gmail')
    parser.add_argument('--hours', type=int, default=0, help='Analyze emails from the last X hours')
    parser.add_argument('--count', type=int, default=15, help='Analyze the last X emails (if hours not provided)')
    args = parser.parse_args()

    print("Łączenie z Gmail API...")
    service = get_gmail_service()
    
    query = ""
    if args.hours > 0:
        past_time = int((datetime.now() - timedelta(hours=args.hours)).timestamp())
        query = f"after:{past_time}"
        print(f"Pobieranie e-maili z ostatnich {args.hours} godzin...")
    else:
        print(f"Pobieranie ostatnich {args.count} e-maili...")

    results = service.users().messages().list(userId='me', q=query, maxResults=args.count if args.hours == 0 else 100).execute()
    messages = results.get('messages', [])

    if not messages:
        print("Nie znaleziono żadnych wiadomości.")
        return

    report_lines = []
    report_lines.append(f"# Raport Antyphishingowy - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report_lines.append("| Nadawca | Temat | Linki | Ocena Ryzyka | Uzasadnienie |")
    report_lines.append("|---|---|---|---|---|")

    found_phishing = False

    for message in messages:
        row = analyze_message(service, message['id'])
        if row:
            report_lines.append(row)
            if "**[PHISHING]**" in row:
                found_phishing = True

    if len(report_lines) == 3:
        report_lines.append("| Brak | Brak | Brak wiadomości z linkami | N/A | N/A |")

    report_content = "\n".join(report_lines)
    
    os.makedirs('reports', exist_ok=True)
    report_filename = f"reports/phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report_content)
        
    print(f"\nAnaliza zakończona. Raport zapisano w: {report_filename}")
    
    if found_phishing:
        print("\n!!! UWAGA: Wykryto potencjalne wiadomości phishingowe (oznaczone [PHISHING]). Nie klikaj w żadne linki w tych wiadomościach! !!!")

if __name__ == '__main__':
    main()
