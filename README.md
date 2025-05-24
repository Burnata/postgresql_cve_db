# Projekt: Baza Danych CVE

## Opis projektu

System służy do importowania, przechowywania i raportowania informacji o podatnościach (CVE) wraz z informacjami o exploitach, poprawkach oraz powiązanych vendorach. Dane są pobierane z plików JSON i ładowane do bazy PostgreSQL.
![Main Page_](https://github.com/user-attachments/assets/0971562c-d617-4e6d-93ac-94b075d92e01)

---

## Wymagania funkcjonalne

1. **Import danych CVE** – masowy import identyfikatorów CVE, podatnych pakietów oraz wyników CVSS z plików JSON.
2. **Rejestrowanie statusu exploitów i poprawek** – zapis informacji, czy dla danej podatności istnieje exploit oraz poprawka.
3. **Rejestrowanie powiązanych vendorów** – przypisanie do każdej podatności listy vendorów (dostawców).
4. **Raportowanie podatności** – generowanie raportów, np. lista podatności Oracle z exploitem i poprawką.
5. **Integralność danych** – spójność danych zapewniona przez klucze obce i unikalność identyfikatorów CVE.
6. **Uwierzytelnianie użytkowników** – system logowania i rejestracji użytkowników.
7. **Panel Administracyjny** – zarządzanie kontami użytkowników (usuwanie, zmiana hasła) dostępne dla użytkownika "Admin".

---

## Potencjalni użytkownicy

- Administratorzy bezpieczeństwa IT
- Zespół DevOps/SysOps
- Audytorzy bezpieczeństwa
- Deweloperzy
- Narzędzia SIEM/SOC
- Analitycy ryzyka
- Administratorzy bazy danych
- Konta serwisowe i aplikacyjne

---

## Struktura bazy danych

![schema](https://github.com/user-attachments/assets/b9dae639-a2d0-4bcf-b0a0-80df9a282f33)

### Tabela: `cve_simple`

| Kolumna          | Typ      | Opis                        |
|------------------|----------|-----------------------------|
| id               | SERIAL   | Klucz główny                |
| cve_id           | TEXT     | Unikalny identyfikator CVE  |
| affected_package | TEXT     | Nazwa podatnego pakietu     |
| score            | REAL     | Wynik podatności (CVSS)     |

### Tabela: `cve_exploit_status`

| Kolumna            | Typ      | Opis                        |
|--------------------|----------|-----------------------------|
| id                 | SERIAL   | Klucz główny                |
| cve_id             | TEXT     | Klucz obcy do `cve_simple`  |
| has_active_exploit | BOOLEAN  | Czy istnieje exploit        |

### Tabela: `cve_fix_status`

| Kolumna   | Typ      | Opis                        |
|-----------|----------|-----------------------------|
| id        | SERIAL   | Klucz główny                |
| cve_id    | TEXT     | Klucz obcy do `cve_simple`  |
| has_fix   | BOOLEAN  | Czy istnieje poprawka       |

### Tabela: `vendors`

| Kolumna     | Typ      | Opis                        |
|-------------|----------|-----------------------------|
| id          | SERIAL   | Klucz główny                |
| cve_id      | TEXT     | Klucz obcy do `cve_simple`  |
| vendor_name | TEXT     | Nazwa vendora               |

### Tabela: `users` (Nowa)

| Kolumna         | Typ      | Opis                                  |
|-----------------|----------|---------------------------------------|
| id              | SERIAL   | Klucz główny                          |
| username        | VARCHAR(80) | Unikalna nazwa użytkownika            |
| password_hash   | TEXT     | Zahaszowane hasło użytkownika         |

#### Relacje

- `cve_simple` jest tabelą główną.
- Pozostałe tabele powiązane są przez `cve_id` (ON DELETE CASCADE).

---

## Struktura katalogów

```json
cves/                                       # Pliki JSON z danymi CVE
import_cve_to_postgres/
    import_cve_simple.py                    # Import danych podstawowych CVE
    import_cve_exploit_and_fix_status.py    # Import statusów exploitów i poprawek
    import_vendors.py                       # Import vendorów
    report_oracle_exploits_with_fixes.py    # Raport podatności Oracle
    k8s/
        postgres.yaml                       # Konfiguracja PostgreSQL (Kubernetes)
    vendors.sql                             # Skrypt SQL do tabeli vendors
flask_app/
    .coverage                               # Raport pokrycia testów
    .env                                    # Zmienne środowiskowe lokalne
    .gitignore                              # Pliki ignorowane przez git
    .well-known/                            # Katalog dla certyfikatów i weryfikacji
    app.py                                  # Główny plik aplikacji Flask
    Dockerfile                              # Plik do budowy obrazu kontenera
    requirements.txt                        # Zależności Pythona
    test_app.py                             # Testy jednostkowe dla aplikacji
    build-multiarch.ps1                     # Skrypt PowerShell do budowy obrazu multi-arch
    build-multiarch.sh                      # Skrypt Shell do budowy obrazu multi-arch
    templates/                              # Szablony HTML
        base.html                           # Bazowy szablon z layoutem strony
        index.html                          # Szablon strony głównej z listą CVE
        detail.html                         # Szablon szczegółów danego CVE
        schema.html                         # Szablon widoku schematu bazy danych
        login.html                          # Szablon strony logowania (Nowy)
        register.html                       # Szablon strony rejestracji (Nowy)
        admin_panel.html                    # Szablon panelu administratora (Nowy)
        admin_edit_user.html                # Szablon edycji użytkownika przez admina (Nowy)
    k8s/                                    # Konfiguracja Kubernetes
        deployment.yaml                     # Plik definicji Deployment
        service.yaml                        # Plik definicji Service
        kustomization.yaml                  # Plik Kustomize
        secret/                             # Katalog z sekretami Kubernetes
```

---

## Sposób działania

1. **Import danych:**
   - Uruchom `import_cve_simple.py` – tworzy i wypełnia tabelę `cve_simple`.
   - Uruchom `import_cve_exploit_and_fix_status.py` – tworzy i wypełnia tabele `cve_exploit_status` i `cve_fix_status`.
   - Uruchom `import_vendors.py` – tworzy i wypełnia tabelę `vendors`.
2. **Raportowanie:**
   - Uruchom `report_oracle_exploits_with_fixes.py` – generuje raport CSV podatności Oracle z exploitem i poprawką.
3. **Aplikacja webowa:**
   - Aplikacja Flask umożliwia przeglądanie bazy CVE przez interfejs webowy
   - Funkcje: filtrowanie, paginacja i wyświetlanie szczegółów CVE
   - Widok schematu bazy danych
   - System logowania i rejestracji użytkowników
   - Panel administracyjny dla użytkownika "Admin" do zarządzania kontami (usuwanie, zmiana hasła)

---

## Aplikacja webowa (Flask)

### Funkcjonalność

Aplikacja webowa dostarcza wygodny interfejs użytkownika do przeglądania bazy danych CVE i zawiera:

- **Listę podatności** z filtrowaniem według:
  - Vendora
  - Dostępności exploita
  - Dostępności poprawki
- **Paginację** wyników
- **Szczegółowy widok** każdej podatności, zawierający:
  - Podstawowe informacje (ID, pakiet, wynik CVSS)
  - Status exploita i poprawki
  - Powiązani vendorzy
  - Ocena ryzyka
  - Linki zewnętrzne do źródeł (NVD, MITRE)
- **Widok schematu bazy danych** pokazujący relacje między tabelami
- **System uwierzytelniania:**
  - Rejestracja nowych użytkowników
  - Logowanie istniejących użytkowników
  - Wylogowywanie
- **Panel Administracyjny (dla użytkownika "Admin"):**
  - Lista zarejestrowanych użytkowników (poza kontem "Admin")
  - Możliwość usunięcia użytkownika
  - Możliwość zmiany hasła użytkownika

### Uruchamianie lokalnie

```bash
cd flask_app
pip install -r requirements.txt
python app.py
```

Aplikacja będzie dostępna pod adresem: <http://localhost:5000>

### Budowa i wdrażanie do Kubernetes

1. **Budowanie obrazu kontenera:**

   ```bash
   cd flask_app
   # Linux/Mac
   ./build-multiarch.sh
   # Windows
   .\build-multiarch.ps1
   ```

2. **Wdrażanie do Kubernetes:**

   ```bash
   cd flask_app/k8s
   kubectl apply -k .
   ```

3. **Dostęp do aplikacji:**
   Aplikacja będzie dostępna przez LoadBalancer na porcie 80, przekierowanym do portu 5000 aplikacji.

   ```bash
   kubectl get svc -n postgres-db cve-flask-app
   ```

### Zmienne środowiskowe

Aplikacja używa następujących zmiennych środowiskowych do konfiguracji połączenia z bazą danych:

- `DB_HOST` - host bazy danych (domyślnie: localhost)
- `DB_PORT` - port bazy danych (domyślnie: 5432)
- `DB_NAME` - nazwa bazy danych (domyślnie: mydatabase)
- `DB_USER` - użytkownik bazy danych (domyślnie: myuser)
- `DB_PASSWORD` - hasło do bazy danych (domyślnie: mypassword)
- `FLASK_SECRET_KEY` - klucz sekretny dla sesji Flask (ważne dla bezpieczeństwa, zalecane ustawienie własnego w `.env`)

W konfiguracji Kubernetes zmienne te są dostarczane przez ConfigMap i Secret.

---

## Wymagania techniczne

- Python 3.x
- PostgreSQL
- Biblioteki: Flask, psycopg2-binary, python-dotenv, Werkzeug
- (Opcjonalnie) Kubernetes do uruchomienia bazy (patrz `postgres.yaml`)

---

## Autorzy i kontakt

Projekt do celów edukacyjnych i demonstracyjnych.
