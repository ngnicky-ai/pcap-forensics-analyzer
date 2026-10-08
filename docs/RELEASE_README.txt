PCAP 침해사고 분석기 v1.1.0 (Windows x64)
=========================================

구성
  PcapForensics.exe   GUI 프로그램 (실행 후 pcap/pcapng 파일을 열거나 창에 끌어다 놓기)
  pcapir.exe          명령줄 도구 (pcapir 파일.pcap --html report.html)
  rules\              탐지 임계값(settings.json), 웹 공격 시그니처(web_attack_rules.json)
  iocs\               IOC 목록 형식 예시

.NET 런타임을 따로 설치할 필요가 없습니다(self-contained).

실시간 모니터링 (선택, Npcap 필요: https://npcap.com)
  GUI [● 실시간 모니터링] 또는  pcapir --capture --duration 60 --max-mb 200
  모든 인터페이스(실제·가상·루프백)를 캡처해 pcapng 로 저장하고,
  중지하거나 용량/시간 제한에 도달하면 자동으로 분석합니다(80% 에서 경고).
  저장 위치: %LocalAppData%\PcapForensics\captures

Suricata 연동 (선택)
  1. winget install OISF.Suricata   (Npcap 필요)
  2. GUI [ET Open 룰 받기] 또는  pcapir --update-rules
  3. GUI [Suricata 검사] 또는  pcapir 파일.pcap --suricata

확대/축소: Ctrl + 마우스 휠, Ctrl + '+' / '-', Ctrl + 0
모든 시각은 UTC 로 표시됩니다.

주의: 추출 파일에는 악성코드가 포함될 수 있습니다. 격리된 분석 환경에서 사용하십시오.
자세한 설명: https://github.com/ngnicky-ai/pcap-forensics-analyzer
