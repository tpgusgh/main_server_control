# Main Server Control

집·개인 리눅스 서버를 한 화면에서 **모니터링·제어·보안 관리**하는 셀프호스팅 대시보드입니다.
Cloudflare Tunnel + Access 뒤에서 동작하고, Tailscale로 묶인 여러 서버를 함께 관리하며,
**로컬 LLM(llama.cpp)** 이 보안·운영 상태를 분석하고 할 수 있는 조치는 직접 처리합니다.

> 외부 서비스 의존 없이 한 대의 저사양 PC(4코어 노트북 CPU, 16GB RAM)에서 전부 돌아가도록 설계했습니다.

---

## 주요 기능

| 영역 | 내용 |
|---|---|
| **모니터링** | CPU·메모리·온도·로드·스왑·디스크·네트워크 실시간, 10초 간격 24시간 그래프, 고부하 구간 자동 기록, 상위 프로세스, 홈 폴더별 용량 |
| **서비스 제어** | systemd 사용자 서비스 켜기/끄기/재시작/부팅 시 자동 실행, 열린 포트(프로세스·실행 폴더), 접속 중 클라이언트, 프로세스 종료 |
| **서버 전원** | 재부팅·종료 버튼 (서버 이름 입력 + 비밀번호 재확인) |
| **여러 서버** | Tailscale 네트워크의 서버를 에이전트로 추가 → 상단 "보는 서버"를 바꾸면 **모든 탭이 그 서버 기준** |
| **접속 로그** | 대시보드 접속 IP·국가 6개월 보관, 원격 서버는 SSH 로그인 기록 |
| **보안** | Cloudflare Access JWT 검증, 비밀번호 3회 실패 시 IP 영구 차단, 신뢰 IP, 세션 관리, SSH 무차별 대입 감지, 방화벽 자동 차단(sm-block) |
| **AI 분석** | 서버별 브리핑·채팅(본체 LLM 사용), 매일 밤 서버별 일일 보고서(15분 간격), 30일 위험도 달력, 기억(가벼운 RAG), 대화 기록 |
| **AI 보안 조사** | 이상 징후(설정 변경·처음 보는 외부 IP의 SSH 로그인·수상한 로그인) 또는 직접 요청 시 Claude가 **허용된 도구만** 골라 한 단계씩 조사(최대 8단계) → 정상/확인 필요/공격 판단, 필요하면 IP 차단·실패 서비스 재시작, 결과 알림 |
| **배우는 AI** | 조사마다 일반화된 교훈을 저장하고, 관리자가 "오판"으로 평가하면 정정으로 기록 → 모든 AI 판단(브리핑·점검·조사)에 반영. 지난 조사 검색 도구로 비슷한 사례도 참고 |
| **토큰 절약** | 매 호출은 새 세션(대화 누적 없음), 5시간 세션 90%↑ 또는 주간 95%↑이면 정기 점검을 건너뛰고 긴급 조사만, 97%↑이면 중지. 하루 자동 조사 40건 상한 |
| **설정 변경 감지** | 매시간 서버마다 로그인 사용자·sudo·SSH 공개키·cron·부팅 서비스·sshd 설정·외부 TCP 포트를 비교, 바뀌면 알림 + AI 조사 |
| **외부 노출 차단** | 서버마다 '외부 차단 모드': 인터넷(공인 IP)에서 오는 연결은 허용 포트만(SSH·Tailscale 항상 허용), LAN·Tailscale·Cloudflare 터널은 그대로. 허용 포트도 IP당 분당 새 연결 30회 초과 시 차단. 끄거나 포트를 여는 변경은 비밀번호 재확인. 모드를 꺼도 '내부 전용 포트'는 인터넷 차단 |
| **노출 감시** | 공유기 UPnP 포트포워딩(카메라가 몰래 여는 것), Cloudflare 터널 주소가 Access 로그인 없이 열리는지 매시간 확인 → 알림 + AI 조사. 카메라·영상 포트(554 RTSP, 8554, 1935, 8000, 37777 …)가 열리면 긴급 조사, AI는 포트를 '내부 전용'으로 닫을 수 있음(여는 건 불가) |
| **공격 IP 공유** | 한 곳에서 차단된 IP(대시보드 차단, AI 차단, SSH 공격)는 sm-block이 설치된 모든 서버 방화벽에도 차단, 해제도 함께 |
| **서버 관리** | 월간 가동률(매달 1일 리포트), 디스크 가득 참 예측(14일 추세), apt 업그레이드 버튼, Wake-on-LAN(꺼진 서버 켜기, 다른 서버를 통해 중계) |
| **AI 활동 패널** | 지금 하는 작업과 경과 시간, Claude 5시간 세션·주간 사용률과 초기화 시각, 오늘 토큰 사용량, 다음 예정 작업(위험 감지·일일 보고서·보안 점검), 최근 작업별 토큰 |
| **6시간 위험 감지** | 6시간마다 자동 브리핑, 위험도 주의 이상이면 디스코드로 "🛡️ AI 위험 감지" 알림 (`SM_AI_BRIEFING_HOURS`) |
| **AI 보안 에이전트** | 주 1회(또는 버튼) 모든 서버 보안 점검 → 100점 점수 + 항목별 양호/주의/취약과 해결법 · 서비스 로그 "AI로 분석"(비밀번호·토큰 가린 뒤 전송) · 처음 보는 IP 로그인을 평소 패턴(국가·시간대·브라우저)과 비교해 수상할 때만 알림 |
| **AI 자동 조치** | 빨간불이 켜지면 할 수 있는 건 처리(실패 서비스 재시작, 공격 IP 차단), 못 하는 것만 알림 |
| **웹사이트 감시** | 등록한 주소를 2분마다 확인, 2번 연속 실패(무응답·5xx) 시 알림과 복구 알림, AI 위험도에 반영 |
| **서비스 로그** | 서비스마다 "로그" 버튼 → 최근 journal (원격 서버의 시스템 서비스 포함) |
| **업데이트·백업** | apt 대기·보안 업데이트 수, 자동 보안 업데이트·재부팅 필요 여부 / 하루 1번 백업, 원격 서버로 자동 복사, 6개월 보관 |
| **기억된 기기** | 로그인한 브라우저에 1년짜리 기기 쿠키(HttpOnly·Secure) → 와이파이·모바일로 IP가 바뀌어도 새 IP 알림 없음, 새 기기일 때만 알림+AI 판단. 비밀번호·Access는 그대로 필요, 보안 탭에서 기기 지우기 |
| **디스코드에서 차단 해제** | 차단 알림 아래 **차단 풀기** 버튼(한 번 더 확인) · DM 명령 `차단목록`, `차단해제 <IP>`. 봇이 디스코드로 먼저 연결하는 방식(Gateway)이라 공개 주소를 새로 열지 않고, 등록된 본인 계정(`SM_DISCORD_USER_ID`)만 사용 가능. 대시보드 차단과 모든 서버 방화벽 차단을 함께 풀어요 |
| **알림** | 디스코드(봇 DM/웹훅, 심각도 색 카드)·텔레그램, 하트비트(서버 전체 다운 감지) |

---

## 구조

```
 브라우저 ──HTTPS──▶ Cloudflare (Access: 이메일 인증)
                         │  Tunnel (cloudflared)
                         ▼
 ┌──────────────── 본체 서버 ─────────────────────────────┐
 │ server-monitor (FastAPI, 127.0.0.1:8100)                 │
 │   ├─ 지표 수집 · systemd 제어 · 접속 로그 (SQLite)       │
 │   ├─ AI 분석가 ──▶ llm.service (llama-server, :8180)     │
 │   └─ NodeHub ──Tailscale──▶ 원격 서버들                   │
 └──────────────────────────────────────────────────────────┘
                         │ (100.x.y.z:8101, 토큰 + 대시보드 IP만 허용)
 ┌──────── 원격 서버 ────────┐
 │ server-agent (표준 라이브러리만) │ ──▶ sm-block (root, 선택)
 └───────────────────────────┘
```

| 파일 | 역할 |
|---|---|
| `app.py` | FastAPI 앱, 보안 미들웨어(Host/Origin/CSRF/Access/차단), 라우터 연결 |
| `core.py` | 설정·DB·신뢰/차단 IP·알림·비밀번호 재확인 등 공통 상태 |
| `monitor.py` | 지표 수집기, 서비스·네트워크·로그, 백업·하트비트, 업데이트 상태, 홈 폴더 용량, 전원, 방화벽 목록 |
| `sites.py` | 웹사이트 감시 (2분 간격, 연속 실패 시 알림) |
| `routes_auth.py` | 페이지, 로그인/로그아웃, 접속 로그, 세션, 신뢰 IP, 차단 |
| `routes_nodes.py` | 원격 서버 추가·수정·프록시(서비스/프로세스/전원/차단 해제) |
| `routes_ai.py` | AI 보고서·채팅·기억, 자동 조치 실행기 |
| `secops.py` | AI 보안 조사(도구 목록·검증), 배운 것(교훈)·관리자 평가, 공격 IP 공유 |
| `fleet.py` | 가동률 기록·월간 리포트, 디스크 예측, 설정 변경 감지, Wake-on-LAN, apt 업그레이드 |
| `agent.py` | AI 분석가: 사실 데이터 구성, 위험도 규칙, 브리핑/일일 보고서, 자동 조치 판단 |
| `nodes.py` | 원격 서버 폴링·지표 저장·SSRF 방지 주소 검증 |
| `alerts.py` `security.py` `cfaccess.py` | 푸시 알림 / 비밀번호·TOTP / Access JWT |
| `node_agent/` | 원격 서버용 에이전트, 설치 스크립트, `sm-block`(방화벽 도구), `hostsec.py` |
| `static/` | 프론트엔드 (빌드 없는 순수 JS, CSP `script-src 'self'`) |
| `deploy/systemd/` | systemd 사용자 서비스 예시 |
| `scripts/harden-ssh.sh` | SSH 키 전용·방화벽·시간대 설정 (sudo 1회) |
| `tests/` | 보안 핵심 로직 자체 테스트 |

---

## 보안 설계

- **외부 노출 없음**: 앱은 `127.0.0.1`에만 바인딩, 외부 접근은 Cloudflare Tunnel 뿐. Access(이메일 인증)를 통과한 요청만 도달하고, 서버도 Access JWT 서명을 다시 검증합니다.
- **로그인**: scrypt 해시, 세션 쿠키 `__Host-` · HttpOnly · Secure · SameSite=Strict, 30분 미사용 만료, CSRF 토큰 + Origin 검사, 엄격한 CSP.
- **차단**: 신뢰 IP가 아니면 비밀번호 3회 실패 시 영구 차단(IPv6는 /64). 신뢰 IP는 차단 대신 대기시간 증가. 위험한 작업(전원)의 비밀번호 재확인 실패도 같은 규칙.
- **AI 보안 에이전트도 읽기 전용**: 점검·로그 분석·로그인 판단은 결과만 보여주고 아무것도 바꾸지 않습니다. 로그는 보내기 전에 비밀값 패턴(password=, Bearer, sk-ant-, gh*_ , 긴 키/JWT)을 `[가림]`으로 바꿉니다.
- **AI 조사관에게 셸·네트워크·파일은 없음**: Claude는 매 단계 JSON으로 '도구 이름'만 고르고, 서버가 인자를 검증해 정해진 함수만 실행합니다(조회 6개 + 조치 2개). 조회 결과는 데이터로만 돌려주며 그 안의 지시는 따르지 않도록 했고, 차단은 관리자 IP(신뢰·이름·로그인/SSH 성공 이력·내부망)를 서버가 다시 거부합니다.
- **에이전트 원격 코드 업데이트는 일부러 없음**: 토큰이 새면 원격 코드 실행 통로가 되므로, 새 버전은 표시만 하고 설치는 사람이 `install.sh`로 합니다.
- **AI는 읽기 전용**: 서버가 집계한 사실만 받고(User-Agent 미전달, 경로는 안전 문자만), 실행은 정해진 목록(재시작·차단)만 서버가 조건을 재검사한 뒤 수행. 외부 노출·차단 해제·인증 끄기는 목록에 없습니다. 프롬프트 인젝션 테스트 포함.
- **원격 에이전트**: Tailscale 주소에만 바인딩, 대시보드 IP 허용 목록 + 서버별 토큰, 자기 자신은 종료 불가. 대시보드는 Tailscale 주소만 등록 가능(SSRF 방지).
- **방화벽 자동 차단(sm-block)**: sudo 권한을 주지 않습니다. 사용자는 요청 파일만 쓰고 root systemd path 유닛이 검증·적용 — 내부망·Tailscale·접속 중인 SSH IP는 절대 차단하지 않습니다.

---

## 설치 (본체 서버)

요구 사항: Ubuntu 24.04+ (systemd), Python 3.12+, [uv](https://github.com/astral-sh/uv), `cloudflared`, Tailscale(여러 서버 관리 시), 선택: llama.cpp

```bash
git clone https://github.com/tpgusgh/main_server_control.git ~/server-monitor
cd ~/server-monitor
uv venv venv && uv pip install --python venv/bin/python -r requirements.txt
cp .env.example .env && chmod 600 .env    # 값 채우기 (아래 환경변수 표)
mkdir -m 700 data
venv/bin/python -m unittest discover -s tests   # 자체 테스트
```

### 1. 서비스 등록 (부팅 시 자동 실행)
```bash
cp deploy/systemd/server-monitor.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now server-monitor
sudo loginctl enable-linger "$USER"     # 로그인하지 않아도 부팅 시 시작
```

### 2. Cloudflare Tunnel + Access
```bash
cloudflared tunnel create dashboard
cloudflared tunnel route dns dashboard hi.example.com
# ~/.cloudflared/dashboard.yml: ingress hi.example.com → http://127.0.0.1:8100
cp deploy/systemd/dashboard-tunnel.service ~/.config/systemd/user/ && systemctl --user enable --now dashboard-tunnel
```
Cloudflare Zero Trust → Access → Applications 에 호스트를 추가(허용 이메일 지정)하고, 팀 도메인과 AUD를 `.env`의 `SM_CF_TEAM_DOMAIN`, `SM_CF_AUD`에 넣습니다. 앱 설정의 Cookies에서 **HTTP Only**, **Binding Cookie**를 켜는 것을 권장합니다.

### 3. 로컬 LLM (선택 — AI 기능)
llama.cpp CPU 빌드(`llama-bXXXX-bin-ubuntu-x64.tar.gz`)와 GGUF 모델(예: Qwen3-4B-Instruct Q4_K_M, 약 2.5GB)을 `~/llm`에 두고 `deploy/systemd/llm.service`를 등록합니다. `~/llm/llm.env`의 `LLAMA_API_KEY`와 `.env`의 `SM_LLM_API_KEY`를 같은 값으로 맞춥니다.
4코어 노트북 CPU 기준 생성 약 5토큰/초 — 보고서 1건 2~5분이라 밤에 서버별로 나눠 실행합니다.

### 3-1. Claude Code 백엔드 (선택 — 로컬 CPU 대신)
로컬 LLM이 CPU·열 부담이면 Claude Code(Pro 이상)를 **개발용과 다른 계정**으로 쓸 수 있습니다.
```bash
mkdir -m 700 ~/.claude-monitor
CLAUDE_CONFIG_DIR=~/.claude-monitor claude setup-token   # 다른 계정으로 로그인 → 1년짜리 토큰 출력
```
`.env`에 `SM_AI_BACKEND=claude`, `SM_CLAUDE_OAUTH_TOKEN=<토큰>`을 넣고 재시작하면 됩니다(`llm.service`는 꺼도 됨).
호출은 `claude -p --safe-mode --tools "" --disallowedTools "mcp__*" --no-session-persistence`로 — **도구·MCP·사용자 설정 없이** 텍스트만 주고받고, `ANTHROPIC_API_KEY`는 제거한 채 실행합니다. 이 경우 AI 입력 데이터(서버 상태·접속 IP 등)는 Anthropic으로 전송됩니다.

### 4. 원격 서버 추가
```bash
scp -r ~/server-monitor/node_agent <user>@<원격_Tailscale_IP>:~/
ssh <user>@<원격_Tailscale_IP> 'bash ~/node_agent/install.sh <본체_Tailscale_IP>'
```
출력된 주소·토큰을 대시보드 **서버 목록 → 서버 추가**에 입력합니다. 다시 설치하면 토큰은 유지되고 에이전트가 새 버전으로 재시작됩니다.

### 5. 선택 (서버마다 sudo 1회)
| 스크립트 | 효과 |
|---|---|
| `node_agent/allow-power.sh` | 재부팅·종료 버튼 활성화 (polkit 규칙, 그 계정에 전원 조작만 허용) |
| `node_agent/install-blocker.sh` | SSH 공격 IP 자동 방화벽 차단·공격 IP 공유, **패키지 업그레이드 버튼** (`sm-block`, 매개변수 없는 고정 apt 명령) — 새 버전이 나오면 다시 실행 |
| `scripts/harden-ssh.sh` | SSH 키 전용, ufw(SSH는 Tailscale·LAN만), 시간대 KST — 키가 없으면 아무것도 바꾸지 않음 |

---

## 환경변수 (`.env`)

| 이름 | 설명 |
|---|---|
| `SM_PASSWORD` | 대시보드 비밀번호(11자 이상). 바꾸면 모든 세션 로그아웃 |
| `SM_TRUSTED_IPS` / `SM_IP_LABELS` | 차단 예외 IP / IP 표시 이름 (대시보드에서도 세션 → "영구 등록" 가능) |
| `SM_HOST` `SM_PORT` | 공개 호스트 이름, 로컬 포트 |
| `SM_CF_TEAM_DOMAIN` `SM_CF_AUD` `SM_CF_ALLOWED_EMAILS` | Cloudflare Access JWT 검증 |
| `SM_DISCORD_BOT_TOKEN` + `SM_DISCORD_USER_ID`/`SM_DISCORD_CHANNEL_ID`, `SM_DISCORD_WEBHOOK`, `SM_TELEGRAM_*` | 알림 |
| `SM_HEARTBEAT_URL` | 외부 하트비트(서버 다운 감지) |
| `SM_LLM_URL` `SM_LLM_API_KEY` | 로컬 LLM |
| `SM_AI_BRIEFING_HOURS` | 자동 위험 감지 간격(기본 6, 0 = 끔). 주의 이상이면 알림 |

---

## 운영

```bash
venv/bin/python manage.py test-alert        # 알림 테스트
venv/bin/python manage.py set-password      # 비밀번호 변경
venv/bin/python manage.py totp-enable       # 2단계 인증
venv/bin/python manage.py bans | unban <IP> # 차단 목록 / 해제 (스스로 차단됐을 때)
```

- **AI 일일 보고서**: 매일 00:00(KST) 본체, 이후 원격 서버마다 15분 간격(00:15, 00:30, …). 놓친 시간은 켜진 뒤 따라잡습니다. 수치·위험도는 규칙 기반, 설명만 AI.
- **보관**: 지표 24시간(48시간 저장), 접속 로그 6개월, 보고서 30일, 대화 1년.
- **백업**: 하루 1번 DB+설정을 `data/backups/`에 저장, **6개월(183개) 보관**. 원격 서버(에이전트 1.8+)에도 같은 백업을 Tailscale로 하루 1번 복사해 6개월 보관(`~/server-agent/backups/`, 권한 600). 복사는 매시 확인하므로 서버가 꺼져 있던 날도 켜지면 따라잡습니다.
- **재부팅 후**: 모든 서비스가 linger로 자동 시작, 터널은 DNS 준비까지 기다렸다가 연결.

## 한계

- 4B 로컬 모델이라 세부 설명이 틀릴 수 있습니다(수치·차단·위험도는 규칙이 결정).
- 원격 서버의 시스템 서비스는 보기만 가능(제어는 root 필요), 원격 홈 용량은 1시간마다 갱신.
- 웹 공격은 Cloudflare 뒤라 IP 차단은 앱 단계에서, 방화벽 차단(sm-block)은 SSH 등 직접 접속에 해당합니다.
