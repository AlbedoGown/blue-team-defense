# Blue Team Defense

Практические проекты по защите инфраструктуры: мониторинг, анализ инцидентов, обнаружение атак.

## Структура

- `siem-detection/` — правила детектирования, корреляция событий в SIEM
- `log-analysis/` — анализ системных и сетевых журналов (Windows Event Logs, сетевые логи)
- `incident-response/` — плайбуки и сценарии реагирования на инциденты
- `network-monitoring/` — анализ сетевого трафика, поиск аномалий
- `threat-hunting/` — проактивный поиск индикаторов компрометации

## Стек и инструменты

Splunk, Wireshark, Sysmon, Windows Event Viewer, VirusTotal (`vt-cli`), Python/PowerShell для автоматизации анализа.

## Сертификация

**LetsDefend SOC Analyst Learning Path** — пройден 14.09.2026. [Проверить сертификат](https://app.letsdefend.io/certificate/show/de9e7d55-b183-4355-ac06-ef1b3fb11970).

Темы пути: основы SOC/SIEM, Cyber Kill Chain, MITRE ATT&CK Framework, анализ фишинговых писем, обнаружение веб-атак (включая практическую лабу по цепочке атаки на bWAPP), расследование SIEM-алертов по плейбуку, основы анализа вредоносного ПО, анализ вредоносных документов, сетевой лог-анализ, Splunk, Cyber Threat Intelligence, работа с VirusTotal для SOC-аналитика.

Детальные разборы реальных алертов из пути — в `siem-detection/`:
- [SOC282 — фишинговое письмо, эскалированное до заражения AsyncRAT с C2](siem-detection/soc282-phishing-free-coffee.md)
- [SOC138 — вредоносный XLSM-документ с макросом-даунлоадером](siem-detection/soc138-malicious-xlsm-macro.md)
