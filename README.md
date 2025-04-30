# Projekt: Baza Danych CVE

## Opis projektu

System służy do importowania, przechowywania i raportowania informacji o podatnościach (CVE) wraz z informacjami o exploitach, poprawkach oraz powiązanych vendorach. Dane są pobierane z plików JSON i ładowane do bazy PostgreSQL.

---

## Wymagania funkcjonalne

1. **Import danych CVE** – masowy import identyfikatorów CVE, podatnych pakietów oraz wyników CVSS z plików JSON.
2. **Rejestrowanie statusu exploitów i poprawek** – zapis informacji, czy dla danej podatności istnieje exploit oraz poprawka.
3. **Rejestrowanie powiązanych vendorów** – przypisanie do każdej podatności listy vendorów (dostawców).
4. **Raportowanie podatności** – generowanie raportów, np. lista podatności Oracle z exploitem i poprawką.
5. **Integralność danych** – spójność danych zapewniona przez klucze obce i unikalność identyfikatorów CVE.

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

#### Relacje

- `cve_simple` jest tabelą główną.
- Pozostałe tabele powiązane są przez `cve_id` (ON DELETE CASCADE).

---

## Struktura katalogów

```json
cves/                  # Pliki JSON z danymi CVE
import_cve_to_postgres/
    import_cve_simple.py                # Import danych podstawowych CVE
    import_cve_exploit_and_fix_status.py# Import statusów exploitów i poprawek
    import_vendors.py                   # Import vendorów
    report_oracle_exploits_with_fixes.py# Raport podatności Oracle
    postgres.yaml                       # Konfiguracja PostgreSQL (Kubernetes)
    vendors.sql                         # Skrypt SQL do tabeli vendors
```

---

## Sposób działania

1. **Import danych:**
   - Uruchom `import_cve_simple.py` – tworzy i wypełnia tabelę `cve_simple`.
   - Uruchom `import_cve_exploit_and_fix_status.py` – tworzy i wypełnia tabele `cve_exploit_status` i `cve_fix_status`.
   - Uruchom `import_vendors.py` – tworzy i wypełnia tabelę `vendors`.
2. **Raportowanie:**
   - Uruchom `report_oracle_exploits_with_fixes.py` – generuje raport CSV podatności Oracle z exploitem i poprawką.

---

## Wymagania techniczne

- Python 3.x
- PostgreSQL
- Biblioteki: psycopg2, python-dotenv
- (Opcjonalnie) Kubernetes do uruchomienia bazy (patrz `postgres.yaml`)

---

## Autorzy i kontakt

Projekt do celów edukacyjnych i demonstracyjnych.
