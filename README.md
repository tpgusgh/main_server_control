# Main Server Control

집·개인 리눅스 서버들을 한 화면에서 **모니터링·제어·보안 관리**하는 셀프호스팅 대시보드입니다.
Cloudflare Tunnel + Access 뒤에서 동작하고, Tailscale로 묶인 여러 서버를 중앙에서 관리하며,
**Claude(별도 계정, 도구 없이)** 가 보안·운영 상태를 분석·조사하고 허용된 조치만 직접 처리합니다.

> 대시보드는 `127.0.0.1`에만 열리고, 원격 서버 에이전트는 표준 라이브러리만 씁니다. 저사양 PC 한 대로 충분합니다.

---

## 주요 기능

### 모니터링·제어
| 기능 | 내용 |
|---|---|
| **실시간 지표** | CPU·메모리·온도·로드·스왑·디스크·네트워크, 10초 간격 24시간 그래프, 고부하 구간 자동 기록, 상위 프로세스, 홈 폴더별 용량 |
| **서비스 제어** | systemd 사용자 서비스 켜기/끄기/재시작/부팅 자동 실행/삭제(휴지통), 서비스 로그, 열린 포트(프로세스·실행 폴더), 접속 중 클라이언트 |
| **전원** | 재부팅·종료 (서버 이름 입력 + 비밀번호 재확인), **재부팅 완료 알림** |
| **여러 서버** | Tailscale 서버를 에이전트로 추가 → 상단 "보는 서버"를 바꾸면 모든 탭이 그 서버 기준 |
| **서버 관리** | 월간 가동률(매달 1일 리포트), 디스크 가득 참 예측(14일 추세), apt 업그레이드 버튼, Wake-on-LAN(다른 서버를 통해 중계), 에이전트 버전 확인 + 복사해서 쓰는 업데이트 명령 |
| **업데이트·백업** | apt 대기·보안 업데이트(Ubuntu 단계적 배포는 따로 표시), 재부팅 필요 여부 / 하루 1번 DB·설정 백업, 원격 서버로 자동 복사, 6개월 보관 |
| **웹사이트 감시** | 등록한 주소를 2분마다 확인, 2번 연속 실패 시 알림·복구 알림 |

### 보안
| 기능 | 내용 |
|---|---|
| **접근 제어** | Cloudflare Access(이메일) + 서버 측 JWT 재검증, 비밀번호(scrypt), 선택 TOTP, 신뢰하지 않는 IP는 3회 실패 시 영구 차단(IPv6 /64) |
| **기억된 기기** | 로그인한 브라우저에 1년짜리 기기 쿠키 → 와이파이·모바일로 IP가 바뀌어도 알림 없음, **새 기기일 때만** 알림 + AI 판단 (비밀번호·Access는 그대로 필요) |
| **외부 차단 모드** | 서버마다 켜는 방화벽(sm-block): 인터넷(공인 IP)에서는 허용 포트만(SSH·Tailscale 항상 허용), LAN·Tailscale·Cloudflare 터널은 그대로, IP당 분당 새 연결 30회 초과 차단. 끄거나 포트를 여는 변경은 비밀번호 재확인 |
| **노출 감시** | 공유기 UPnP 포트포워딩(카메라가 몰래 여는 것), Cloudflare 터널 주소가 Access 없이 열리는지 매시간 확인. 카메라·영상 포트(554 RTSP, 8554, 1935, 8000, 37777 …)가 열리면 긴급 조사 |
| **설정 변경 감지** | 매시간 로그인 사용자·sudo·SSH 공개키·cron·부팅 서비스·sshd 설정·외부 TCP 포트·UPnP·터널 주소를 비교, 바뀌면 알림 + AI 조사 |
| **공격 IP 공유** | 한 곳에서 막힌 IP(대시보드 차단, AI 차단, SSH 공격)는 모든 서버 방화벽에서 차단, 해제도 함께 |
| **디스코드 제어** | 차단 알림 아래 **차단 풀기** 버튼(한 번 더 확인), DM 명령 `차단목록` · `차단해제 <IP>`. 봇이 먼저 연결하는 방식(Gateway)이라 공개 주소를 새로 열지 않고, 본인 계정만 사용 가능 |
| **알림** | 디스코드 봇 DM(심각도 색 카드)·웹훅·텔레그램, 하트비트(서버 전체 다운 감지) |

### AI (Claude)
| 기능 | 내용 |
|---|---|
| **AI 보안 조사관** | 이상 징후(설정 변경, 처음 보는 외부 IP의 SSH 로그인, 수상한 로그인) 또는 직접 요청 시 **허용된 도구만** 골라 한 단계씩 조사(최대 8단계) → 정상/확인 필요/공격 판단. 조치는 IP 차단, 실패 서비스 재시작, 포트를 '내부 전용'으로 닫기(여는 건 불가) |
| **배우는 AI** | 조사마다 교훈을 저장하고, 관리자가 "오판"으로 평가하면 정정으로 기록 → 이후 모든 AI 판단에 반영. 지난 조사 검색으로 비슷한 사례 참고 |
| **자동 위험 감지** | 6시간마다 브리핑, 위험도 주의 이상이면 알림. 매일 밤 서버별 일일 보고서(15분 간격), 30일 위험도 달력 |
| **보안 점검** | 주 1회(또는 버튼) 모든 서버 점검 → 100점 점수 + 항목별 양호/주의/취약과 해결법 |
| **자동 조치** | 빨간불이 켜지면 할 수 있는 건 처리(실패 서비스 재시작, 공격 IP 차단), 못 하는 것만 알림 |
| **로그 분석·로그인 판단** | 서비스 로그 "AI로 분석"(비밀값 가린 뒤 전송), 처음 보는 기기 로그인을 평소 패턴과 비교해 수상할 때만 알림 |
| **활동 패널·토큰 절약** | 지금 하는 작업과 경과 시간, 5시간 세션·주간 사용률과 초기화 시각, 작업별 토큰. 매 호출은 새 세션(누적 없음), 5시간 90%↑이면 긴급 작업만, 97%↑이면 중지, 하루 자동 조사 40건 상한 |
| **채팅·기억** | 서버 데이터로 답하는 채팅, "기억해: …"로 선호 저장(가벼운 RAG), 대화 기록 1년 |

---

## 구조

```
 브라우저 ──HTTPS──▶ Cloudflare (Access: 이메일 인증)
                         │  Tunnel (cloudflared)
                         ▼
 ┌──────────────── 중앙서버 ──────────────────────────────────┐
 │ server-monitor (FastAPI, 127.0.0.1:8100, SQLite)            │
 │   ├─ 지표 수집 · systemd 제어 · 접속 로그 · 백업            │
 │   ├─ AI 분석가/조사관 ──▶ claude -p (도구·MCP 없음, 별도 계정)│
 │   ├─ 디스코드 봇 ──▶ Discord Gateway (밖으로만 연결)        │
 │   └─ NodeHub ──Tailscale──▶ 원격 서버들                      │
 └─────────────────────────────────────────────────────────────┘
                         │ (100.x.y.z:8101, 토큰 + 대시보드 IP만 허용)
 ┌──────── 원격 서버 ──────────────┐
 │ server-agent (표준 라이브러리만) │ ──▶ sm-block (root, 방화벽·apt)
 └─────────────────────────────────┘
```

| 파일 | 역할 |
|---|---|
| `app.py` | FastAPI 앱, 보안 미들웨어(Host/Origin/CSRF/Access/차단), 라우터·백그라운드 작업 연결 |
| `core.py` | 설정·DB·신뢰/차단 IP·알림·차단 해제·비밀번호 재확인 등 공통 상태 |
| `monitor.py` | 지표 수집기, 서비스·네트워크·로그, 백업·하트비트, 업데이트 상태, 홈 폴더 용량, 전원 |
| `routes_auth.py` | 페이지, 로그인(기억된 기기), 접속 로그, 세션, 신뢰 IP, 차단 |
| `routes_nodes.py` / `nodes.py` | 원격 서버 추가·수정·프록시 / 폴링·지표 저장·SSRF 방지 주소 검증 |
| `agent.py` | AI 분석가: Claude 호출, 사실 데이터 구성, 위험도 규칙, 브리핑·일일 보고서·점검, 자동 조치 판단, 토큰 절약 |
| `routes_ai.py` | AI 보고서·채팅·기억 API, 자동 조치 실행기 |
| `secops.py` | AI 보안 조사(도구 목록·검증), 교훈·관리자 평가, 공격 IP 공유 |
| `fleet.py` | 가동률·월간 리포트, 디스크 예측, 설정 변경 감지, 재부팅 감지, 외부 차단 모드·노출 점검, WoL, apt 업그레이드 |
| `discord_bot.py` | 디스코드 버튼·DM 명령(차단 해제) |
| `sites.py` | 웹사이트 감시 |
| `alerts.py` `security.py` `cfaccess.py` | 푸시 알림 / 비밀번호·TOTP / Access JWT |
| `node_agent/` | 원격 서버용 에이전트(2.2), 설치 스크립트, `sm-block`(root 도구), `hostsec.py`(중앙·원격 공용) |
| `static/` | 프론트엔드 (빌드 없는 순수 JS, CSP `script-src 'self'`) |
| `deploy/systemd/` | systemd 사용자 서비스 예시 |
| `tests/` | 보안 핵심 로직 자체 테스트 |

---

## 보안 설계

- **외부 노출 없음**: 앱은 `127.0.0.1`에만 바인딩, 외부 접근은 Cloudflare Tunnel뿐. Access를 통과한 요청만 도달하고 서버가 JWT 서명을 다시 검증합니다. 디스코드 봇도 밖으로만 연결합니다.
- **로그인**: scrypt 해시, 세션 쿠키 `__Host-` · HttpOnly · Secure · SameSite=Strict, 30분 미사용 만료, CSRF 토큰 + Origin 검사, 엄격한 CSP. 기기 쿠키는 알림만 줄이고 인증을 대신하지 않습니다.
- **AI에게 셸·네트워크·파일은 없음**: `claude -p --safe-mode --tools "" --disallowedTools "mcp__*" --no-session-persistence`, `ANTHROPIC_API_KEY` 제거, 별도 설정 폴더. 조사관은 매 단계 JSON으로 '도구 이름'만 고르고, 서버가 인자를 검증해 정해진 함수만 실행합니다. 조회 결과는 데이터로만 돌려주며 그 안의 지시는 따르지 않습니다.
- **관리자는 절대 안 막음**: 신뢰·이름 붙인 IP, 로그인·SSH 성공 이력이 있는 IP(대역), 직접 차단을 푼 IP, 내부망·Tailscale은 AI·자동 차단·공유 차단 모두 서버가 거부합니다.
- **AI가 할 수 없는 것**: 포트 열기, 차단 해제, 인증 끄기, 데이터 외부 전송, 서비스 중지·삭제. 로그는 보내기 전에 비밀값(password=, Bearer, sk-ant-, gh*_, 긴 키/JWT)을 `[가림]`으로 바꿉니다.
- **sm-block (root)**: sudo 권한을 주지 않습니다. 사용자는 요청 파일만 쓰고 root path 유닛이 검증·적용합니다. SSH 포트·Tailscale은 닫을 수 없고, apt는 매개변수 없는 고정 명령(설정 유지, 패키지 삭제 없음)만 실행합니다.
- **원격 에이전트**: Tailscale 주소에만 바인딩, 대시보드 IP 허용 목록 + 서버별 토큰. 원격 코드 업데이트는 일부러 없습니다(토큰이 새면 코드 실행 통로가 되므로) — 새 버전은 표시만 하고 설치는 사람이 합니다.

---

## 설치 (중앙서버)

요구 사항: Ubuntu 24.04+ (systemd), Python 3.12+, [uv](https://github.com/astral-sh/uv), `cloudflared`, Tailscale(여러 서버 관리 시), Claude Code CLI(AI 기능), `nftables`(방화벽)

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

### 3. AI (Claude Code, 개발용과 다른 계정)
```bash
mkdir -m 700 ~/.claude-monitor
CLAUDE_CONFIG_DIR=~/.claude-monitor claude setup-token   # 다른 계정으로 로그인 → 1년짜리 토큰 출력
```
`.env`에 `SM_CLAUDE_OAUTH_TOKEN=<토큰>`을 넣고 재시작합니다. AI 입력 데이터(서버 상태·접속 IP 등)는 Anthropic으로 전송됩니다.

### 4. 원격 서버 추가
```bash
# ① 중앙서버에서
scp -r ~/server-monitor/node_agent <user>@<원격_Tailscale_IP>:~/
# ② 원격 서버에서
bash ~/node_agent/install.sh <중앙_Tailscale_IP>
```
출력된 주소·토큰을 대시보드 **서버 목록 → 서버 추가**에 입력합니다. 다시 설치하면 토큰은 유지되고 새 버전으로 재시작됩니다(업데이트할 때도 같은 두 단계 — 대시보드가 명령을 복사 버튼과 함께 보여줍니다).

### 5. 서버마다 sudo 1회
| 스크립트 | 효과 |
|---|---|
| `node_agent/install-blocker.sh` | `sm-block`: 외부 차단 모드, 공격 IP 자동 차단·공유, 패키지 업그레이드 버튼 — 새 버전이 나오면 다시 실행 |
| `node_agent/allow-power.sh` | 재부팅·종료 버튼 활성화 (polkit 규칙, 그 계정에 전원 조작만 허용) |
| `scripts/harden-ssh.sh` | SSH 키 전용, ufw(SSH는 Tailscale·LAN만), 시간대 KST — 키가 없으면 아무것도 바꾸지 않음 |

설치 후 대시보드 **보안 탭 → 외부 노출 차단**에서 서버마다 외부 차단 모드를 켜세요.

---

## 환경변수 (`.env`)

| 이름 | 설명 |
|---|---|
| `SM_PASSWORD` | 대시보드 비밀번호(11자 이상). 바꾸면 모든 세션 로그아웃 |
| `SM_TRUSTED_IPS` / `SM_IP_LABELS` | 차단 예외 IP / IP 표시 이름 (대시보드 세션 목록에서도 "영구 등록" 가능) |
| `SM_HOST` `SM_PORT` | 공개 호스트 이름, 로컬 포트 |
| `SM_CF_TEAM_DOMAIN` `SM_CF_AUD` `SM_CF_ALLOWED_EMAILS` | Cloudflare Access JWT 검증 |
| `SM_CLAUDE_OAUTH_TOKEN` `SM_CLAUDE_MODEL` `SM_CLAUDE_CONFIG_DIR` | AI (Claude Code, 별도 계정) |
| `SM_AI_BRIEFING_HOURS` | 자동 위험 감지 간격(기본 6, 0 = 끔) |
| `SM_DISCORD_BOT_TOKEN` + `SM_DISCORD_USER_ID` | 디스코드 봇 DM 알림 + 버튼/명령 (본인 계정 ID) |
| `SM_DISCORD_WEBHOOK`, `SM_TELEGRAM_*` | 그 밖의 알림 채널 |
| `SM_HEARTBEAT_URL` | 외부 하트비트(서버 다운 감지) |
| `SM_IGNORE_FAILED_UNITS` | 실패해도 알리지 않을 무해한 서비스 |

---

## 운영

```bash
venv/bin/python manage.py test-alert        # 알림 테스트
venv/bin/python manage.py set-password      # 비밀번호 변경
venv/bin/python manage.py totp-enable       # 2단계 인증 (인증 앱 등록)
venv/bin/python manage.py bans | unban <IP> # 차단 목록 / 해제 (스스로 차단됐을 때, 디스코드 DM으로도 가능)
sudo sm-block guard                         # 외부 차단 모드 설정·규칙 보기
```

- **자동 일정**: 6시간마다 위험 감지, 매일 00:00(KST) 중앙 → 원격 서버마다 15분 간격 일일 보고서, 주 1회 보안 점검, 매시간 설정 변경·노출·디스크 기록, 매달 1일 가동률 리포트.
- **보관**: 지표 24시간(48시간 저장), 접속 로그·알림 6개월, 보고서 30일, AI 조사 6개월, 대화 1년, 디스크 기록 60일, 백업 6개월.
- **백업**: 하루 1번 DB+설정을 `data/backups/`에, 원격 서버(`~/server-agent/backups/`, 권한 600)에도 Tailscale로 복사. 꺼져 있던 서버도 켜지면 따라잡습니다.
- **재부팅 후**: 모든 서비스가 linger로 자동 시작, 터널은 DNS 준비까지 기다렸다가 연결, 재부팅 완료 알림 발송.

## 한계

- AI 설명은 참고용입니다(수치·차단·위험도는 규칙이 결정). AI 사용량은 연결한 Claude 계정 한도 안에서 동작합니다.
- 원격 서버의 시스템 서비스는 보기만 가능(제어는 root 필요), 원격 홈 용량은 1시간마다 갱신.
- 웹 공격은 Cloudflare 뒤라 IP 차단은 앱 단계에서, 방화벽 차단(sm-block)은 SSH 등 직접 접속에 해당합니다.
- Wake-on-LAN은 BIOS/NIC 설정이 필요하고 유선 랜에서만 확실히 동작합니다.
- 카메라 자체의 인터넷 접속(P2P 클라우드)과 공유기 UPnP는 서버가 막을 수 없습니다 — 공유기에서 끄세요.
