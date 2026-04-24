# 🛡️ Gmail Phishing Analyzer

W pełni automatyczny skrypt Python do monitorowania i analizowania wiadomości e-mail w Gmailu pod kątem zaawansowanych ataków phishingowych. 

Skrypt wykorzystuje API Gmaila do pobierania poczty, a następnie poddaje ją wieloetapowej weryfikacji. Jeśli algorytm uzna wiadomość za próbę oszustwa, automatycznie nada jej w skrzynce wyraźną, czerwoną etykietę **Phishing** oraz wygeneruje szczegółowy raport Markdown na dysku.

## 🚀 Jak to działa?

Gdy skrypt pobiera nową wiadomość, analizuje ją pod kątem następujących zagrożeń:
1. **Analiza Kontekstowa:** Wykrywa słowa kluczowe budujące presję czasu lub strach (np. "zablokowane konto", "pilne", "weryfikacja", "natychmiast").
2. **Weryfikacja Domeny Nadawcy:** Porównuje oryginalną domenę, z której wysłano e-mail (np. `paypal-support@scam.com`), z właściwymi adresami URL zaszytymi pod przyciskami (np. kliknij tutaj -> `http://malicious.com/login`).
3. **Typosquatting:** Skrypt oblicza [odległość Levenshteina](https://pl.wikipedia.org/wiki/Odleg%C5%82o%C5%9B%C4%87_Levenshteina) dla wyodrębnionych linków względem znanych marek (np. wykryje, że `g00gle.com` lub `paypa1.com` to oszustwo).

## 🛠️ Wymagania

- Zainstalowany **Python 3.x**
- Posiadanie konta Google (Gmail)

## 📦 Instalacja

1. Sklonuj to repozytorium na swój dysk:
   ```bash
   git clone https://github.com/TwojaNazwa/phishing-analyzer.git
   cd phishing-analyzer
   ```
2. Zainstaluj niezbędne biblioteki Pythona:
   ```bash
   python -m pip install -r requirements.txt
   ```

## 🔑 Konfiguracja dostępu (Google Cloud Console)

Aby skrypt miał prawo bezpiecznie czytać Twoją skrzynkę bez podawania hasła, musisz utworzyć własny plik `credentials.json` przez protokół OAuth 2.0. To standardowa procedura narzucana przez Google dla zewnętrznych skryptów.

1. Wejdź na [Google Cloud Console](https://console.cloud.google.com/).
2. Utwórz nowy projekt i przejdź do **APIs & Services > Library**.
3. Wyszukaj i włącz (**Enable**) usługę **Gmail API**.
4. W zakładce **OAuth consent screen** wybierz typ **External**, wypełnij nazwę i zapisz. **Ważne:** Na samym dole w sekcji **Test users** dodaj swój prywatny e-mail, którym będziesz logował się w skrypcie.
5. Przejdź do zakładki **Credentials**, kliknij **Create Credentials** -> **OAuth client ID**. 
6. Wybierz typ: **Desktop app**.
7. Pobierz plik JSON ze swoim kluczem, zmień jego nazwę dokładnie na `credentials.json` i wrzuć go do głównego folderu tego skryptu.

## 🏃 Uruchomienie ręczne

Aby pobrać i przeanalizować ostatnie 15 wiadomości, uruchom:
```bash
python analyzer.py --count 15
```

Przy pierwszym uruchomieniu otworzy się przeglądarka z prośbą o zalogowanie się Twoim kontem Gmail. Po potwierdzeniu zgód, obok skryptu pojawi się nowy plik `token.json`, a system wygeneruje raport w folderze `reports/`.

## ⚙️ Harmonogram Windows (Codziennie o 9:00)

Skrypt jest przygotowany do pracy w tle. Uruchom konsolę Windows PowerShell **jako administrator** w folderze projektu i wpisz:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_schedule.ps1
```

Zadanie automatycznie zapisze się w Twoim Harmonogramie Zadań (Task Scheduler). Od teraz Twój komputer będzie codziennie rano pobierał maile z ostatnich 24 godzin, filtrował je i oflagowywał oszustów.

---
*⚠️ Zastrzeżenie: Ten projekt jest narzędziem wspomagającym i bazuje na heurystyce. Żaden automat nie daje 100% pewności, dlatego zawsze zachowaj zdrowy rozsądek i czujność przy klikaniu w linki.*
