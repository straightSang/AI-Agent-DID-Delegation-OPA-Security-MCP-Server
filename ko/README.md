```markdown
# AI Agent DID, Delegation & OPA Security MCP Server

Spring Boot와 Spring AI MCP Server로 만든 **AI Agent DID 신원/권한위임/정책집행 보안 실험 프로젝트**.

> 보안 구조 학습/검증용 프로젝트
> 참고한 자료
> [CAPMAS: Capability-Based Delegation of Privileges in Multi-Agent Systems](https://arxiv.org/abs/2609.06500)
> [AI Agents with DID and Verifiable Credentials](https://arxiv.org/abs/2511.02841)
----


모든 MCP 도구 요청은 아래 증거를 순서대로 검증한다.

1. Ed25519 개인키 소유 증명
2. `did:key` 기반 Agent 신원
3. 서명된 권한 위임 체인
4. `requestId` 재사용 방지
5. OPA 정책 판단
6. 고위험 작업의 사용자 승인
7. 요청/응답 해시와 서명 감사 원장


## 목차

- [핵심 기능](#핵심-기능)
- [전체 구조](#전체-구조)
- [보안 검증 순서](#보안-검증-순서)
- [권한 축소 규칙](#권한-축소-규칙)
- [프로젝트 구조](#프로젝트-구조)
- [빠른 시작](#빠른-시작)
- [사용자와 Agent DID 생성](#사용자와-agent-did-생성)
- [신뢰 DID 등록](#신뢰-did-등록)
- [서버 실행](#서버-실행)
- [Challenge 발급과 서명](#challenge-발급과-서명)
- [위임 토큰 생성](#위임-토큰-생성)
- [MCP 도구](#mcp-도구)
- [테스트와 공격 검증](#테스트와-공격-검증)
- [AWS 확장](#aws-확장)
- [현재 한계와 다음 작업](#현재-한계와-다음-작업)
- [GitHub 업로드 전 확인](#github-업로드-전-확인)

## 핵심 기능

| 영역 | 구현 내용 | 상태 |
| --- | --- | --- |
| Agent 신원 | Ed25519, `did:key`, Challenge 서명, 일회 사용 | 구현 |
| 권한 위임 | 서명된 위임 토큰, root issuer 신뢰, 체인 검증 | 구현 |
| 권한 감쇠 | action/resource/만료/depth/audience 축소 강제 | 구현 |
| Replay 방지 | Challenge와 `requestId` 재사용 거부 | 구현 |
| 정책 판단 | OPA Rego 정책, fail-closed 처리 | 구현 |
| 위험 승인 | 위험 분류, 요청 해시 결합, 승인 토큰 서명/만료/일회 사용 | 핵심 구현 |
| 감사 증거 | request/response hash, hash chain, Gateway 서명, Merkle root | 핵심 구현 |
| 외부 앵커 | 로컬/S3 Object Lock 구현 경계 | 선택 구성 |
| AWS 상태 저장 | DynamoDB, KMS, S3용 구현과 Terraform | 실험 단계 |

## 전체 구조

```mermaid
flowchart LR
    C[MCP Client / Agent]
    T[Spring AI MCP Tools]
    G[SecurityGateway]
    I[DID + Challenge]
    D[Delegation Verifier]
    R[Replay Protection]
    O[OPA Policy]
    A[Risk + Approval]
    S[Business Service]
    L[Signed Audit Ledger]

    C --> T --> G
    G --> I --> D --> R --> O --> A --> S --> L
```

보안 판단과 비즈니스 실행을 분리함.

- **OPA(PDP)**: 정책 평가, `ALLOW` / `ALLOW_LOG` / `REQUIRE_APPROVAL` / `DENY` 반환
- **SecurityGateway(PEP)**: 검증 순서 강제, `DENY`면 실제 서비스 호출 안 함
- **Service**: 계산/문서 읽기 같은 기능만 수행, 보안 검사 우회 불가

## 보안 검증 순서

```text
MCP Tool 요청
    ↓
Agent DID + Challenge 서명 검증
    ↓
위임 토큰 서명과 체인 검증
    ↓
requestId 일회 사용 검사
    ↓
OPA 정책 판단
    ↓
위험 분류와 사용자 승인 검사
    ↓
실제 도구 실행
    ↓
요청/응답 해시 및 서명 감사 이벤트 기록
```

하나라도 실패하면 요청이 실행되지 않는다.

## 권한 축소 규칙

자식 Agent는 부모보다 넓은 권한을 받을 수 없다.

```text
child.actions ⊆ parent.actions
child.resources ⊆ parent.resources
child.expiresAt ≤ parent.expiresAt
child.delegationDepth = parent.delegationDepth + 1
child.delegationDepth ≤ maxDepth
child.issuer = parent.subject
child.audience = parent.audience
```

서버가 범위를 알아서 줄여주지 않음. 권한 확대가 발견되면 그냥 거부.

## 프로젝트 구조

```text
mcp-server-spring/
├── Dockerfile
├── pom.xml
├── README.md
├── opa/
│   └── policies/
│       └── agent_authz.rego
├── infra/
│   └── aws/
│       └── main.tf
├── src/
│   ├── main/
│   │   ├── java/io/github/straightsang/agentsecurity/mcp/
│   │   │   ├── identity/       # Ed25519, DID, Challenge, Agent 증명
│   │   │   ├── delegation/     # 위임 토큰 정규화/서명/폐기
│   │   │   ├── security/       # 위임 검증, Replay, 요청 해시
│   │   │   ├── opa/            # OPA 입력과 HTTP 연동
│   │   │   ├── approval/       # 위험 분류와 승인 토큰
│   │   │   ├── gateway/        # 전체 검증 순서 강제
│   │   │   ├── audit/          # 서명 원장, Merkle, 외부 앵커
│   │   │   ├── tools/          # MCP 도구 진입점
│   │   │   ├── service/        # 실제 비즈니스 기능
│   │   │   └── state/          # 메모리/DynamoDB 상태 저장
│   │   └── resources/
│   │       └── application.yml
│   └── test/
│       └── java/io/github/straightsang/agentsecurity/mcp/
│           ├── demo/            # DID/Challenge/위임 CLI
│           └── ...              # 단위/보안 테스트
└── .secrets/                    # 실행 후 생성, Git/Docker 제외
```

## 빠른 시작

### 요구 사항

- Windows 10/11 + WSL2 Ubuntu
- Docker Desktop + WSL Integration
- Git
- 인터넷 연결 (최초 Docker 이미지/Maven 의존성 다운로드)

Java, Maven 로컬 설치 없이 Docker 빌드만으로 실행 가능.

### 프로젝트 폴더로 이동

```bash
cd /mnt/c/Users/<사용자명>/OneDrive/Desktop/IHHH_AI_STUDY/W7_DID/mcp-server-spring
```

### Docker 네트워크 생성

최초 한 번만.

```bash
docker network create agent-security-net
```

이미 존재한다는 오류 뜨면 무시하고 다음 단계로.

### OPA 실행

```bash
docker run -d \
  --name opa \
  --network agent-security-net \
  -p 8181:8181 \
  -v "$PWD/opa/policies:/policies:ro" \
  openpolicyagent/opa:latest \
  run --server --addr=0.0.0.0:8181 /policies
```

상태 확인.

```bash
curl http://127.0.0.1:8181/health
```

정상이면 HTTP 200에 `{}`.

## 사용자와 Agent DID 생성

학습용 CLI는 `src/test`에 있음, 운영 JAR에는 안 들어감.

```bash
docker run --rm -it \
  -v "$PWD:/workspace" \
  -v maven-repository:/root/.m2 \
  -w /workspace \
  maven:3.9-eclipse-temurin-21 \
  mvn -q -DskipTests test-compile \
  org.codehaus.mojo:exec-maven-plugin:3.5.0:java \
  -Dexec.mainClass=io.github.straightsang.agentsecurity.mcp.demo.LocalIdentitySetupCli \
  -Dexec.classpathScope=test
```

결과 확인.

```bash
ls -la .secrets
cat .secrets/user.did
cat .secrets/agent.did
```

생성 파일:

```text
.secrets/
├── user-private.pkcs8.b64
├── user-public.x509.b64
├── user.did
├── agent-private.pkcs8.b64
├── agent-public.x509.b64
└── agent.did
```

> `*-private.pkcs8.b64`는 터미널 캡처, 채팅, GitHub, 문서 어디에도 올리지 말 것.

## 신뢰 DID 등록

`src/main/resources/application.yml`의 빈 목록에 **사용자 DID** 등록.

```yaml
security:
  opa:
    url: ${OPA_URL:http://127.0.0.1:8181}
    timeout: 2s

  delegation:
    audience: agent-security-mcp
    max-depth: 3
    trusted-issuers:
      - "did:key:여기에_사용자_DID"

  approval:
    token-ttl: 2m
    trusted-approvers:
      - "did:key:여기에_사용자_DID"
```

- `trusted-issuers`: 최초 root 위임 토큰 발급 가능한 사용자
- `trusted-approvers`: 고위험 요청 승인 가능한 사용자
- Agent DID는 이 두 목록에 넣지 않음
- 목록 비어있으면 fail-closed라 최초 위임/고위험 승인 자체가 거부됨

## 서버 실행

### Docker 이미지 빌드

```bash
docker build -t agent-security-mcp .
```

Dockerfile의 Maven build stage가 `mvn clean verify`를 돌리므로 테스트 실패하면 이미지 자체가 안 만들어짐.

### 로컬 프로필 실행

```bash
docker run --rm \
  --name agent-security-mcp \
  --network agent-security-net \
  -p 8000:8000 \
  -e SERVER_ADDRESS=0.0.0.0 \
  -e OPA_URL=http://opa:8181 \
  -e SPRING_PROFILES_ACTIVE=local \
  agent-security-mcp
```

다른 터미널에서 확인.

```bash
curl http://127.0.0.1:8000/ping
curl http://127.0.0.1:8000/actuator/health
```

정상 응답:

```json
{"status":"Healthy"}
```

```json
{"groups":["liveness","readiness"],"status":"UP"}
```

> `SPRING_PROFILES_ACTIVE=local` 빠뜨리면 Spring Security 기본 설정 때문에 `/ping`이 401 뜸.

## Challenge 발급과 서명

Challenge는 특정 Agent DID에 발급되는 2분짜리 일회용 난수.

### Challenge 발급

```bash
AGENT_DID=$(cat .secrets/agent.did)

curl -X POST http://127.0.0.1:8000/identity/challenges \
  -H "Content-Type: application/json" \
  -d "{\"agentDid\":\"$AGENT_DID\"}"
```

응답 예시:

```json
{
  "challengeId": "6301966b-...",
  "challenge": "Agent가_서명할_난수",
  "expiresAt": "2026-11-12T...Z"
}
```

### Agent 개인키로 서명

`challengeId`가 아니라 응답의 `challenge` 문자열을 서명.

```bash
CHALLENGE='서버_응답의_challenge_값'

docker run --rm -it \
  -v "$PWD:/workspace" \
  -v maven-repository:/root/.m2 \
  -w /workspace \
  maven:3.9-eclipse-temurin-21 \
  mvn -q -DskipTests test-compile \
  org.codehaus.mojo:exec-maven-plugin:3.5.0:java \
  -Dexec.mainClass=io.github.straightsang.agentsecurity.mcp.demo.ChallengeSignerCli \
  -Dexec.classpathScope=test \
  -Dexec.args="$CHALLENGE"
```

출력된 `challengeSignature`를 MCP 요청에 씀. 서명 검증 성공한 Challenge만 소비되고, 잘못된 서명이 Challenge를 바로 무효화하진 않음.

## 위임 토큰 생성

아래 CLI는 사용자가 Agent에게 `calculator_add` / `calculator` 권한을 15분 동안 위임하는 root 토큰을 만듦.

```bash
docker run --rm -it \
  -v "$PWD:/workspace" \
  -v maven-repository:/root/.m2 \
  -w /workspace \
  maven:3.9-eclipse-temurin-21 \
  mvn -q -DskipTests test-compile \
  org.codehaus.mojo:exec-maven-plugin:3.5.0:java \
  -Dexec.mainClass=io.github.straightsang.agentsecurity.mcp.demo.DelegationTokenCli \
  -Dexec.classpathScope=test
```

```bash
cat .secrets/root-delegation-token.json
```

root 토큰 핵심 필드:

| 필드 | 의미 |
| --- | --- |
| `issuer` | 권한을 위임한 사용자 DID |
| `subject` | 권한을 받은 Agent DID |
| `audience` | 토큰을 쓸 MCP 서버 |
| `actions` | 허용된 행동 |
| `resources` | 접근 가능한 리소스 |
| `issuedAt`, `expiresAt` | 발급/만료 시각 |
| `delegationDepth` | 위임 단계, root는 0 |
| `signature` | issuer의 Ed25519 서명 |

## MCP 도구

MCP Streamable HTTP 엔드포인트는 `/mcp`.

### `calculator_add`

정수 두 개를 더한다.

| 입력 | 설명 |
| --- | --- |
| `a`, `b` | 계산할 정수 |
| `agentDid` | 현재 Agent의 `did:key` |
| `challengeId` | 발급된 Challenge ID |
| `challengeSignature` | Agent Ed25519 서명 |
| `requestId` | 매 요청마다 새로 만드는 일회용 ID |
| `delegationChain` | root부터 현재 Agent까지의 위임 토큰 목록 |
| `approvalToken` | 고위험 요청용 승인 토큰, 계산에서는 보통 `null` |

정책 입력에서는 이렇게 평가됨.

```text
action   = calculator_add
resource = calculator
```

### `read_lab_document`

허용된 sandbox 상대 경로의 문서를 읽음.

```text
action   = read_lab_document
resource = 요청한 상대 경로
```

`LabDocumentService`가 경로 정규화와 sandbox 경계 검사를 함. 운영에서는 symlink 우회 막기 위한 `toRealPath()` 검증도 추가해야 함.

## OPA 정책

정책 파일은 `opa/policies/agent_authz.rego`.

기본값은 항상 거부.

```rego
default allow := false
```

아래 조건이 전부 True가 돼야 정책 평가를 계속 진행한다.

- 신원 인증 성공
- 위임 체인 검증 성공
- 현재 actor와 최종 위임 subject 일치
- 요청 action이 위임 범위에 포함
- 요청 resource가 위임 범위에 포함

OPA 연결 실패, timeout, 잘못된 응답 형식은 허용으로 처리되지 않도록 설정했다.

## 위험 승인

위험 분류 결과는 네 종류.

| 결과 | 처리 |
| --- | --- |
| `ALLOW` | 즉시 실행 |
| `ALLOW_LOG` | 실행 후 강화 로그 기록 |
| `REQUIRE_APPROVAL` | 사용자 승인 토큰 검증 후 실행 |
| `DENY` | 실행 차단 |

`POST /approval/prepare`는 승인 화면에 보여줄 위험 설명과 `requestHash`를 준비함.

승인 토큰은 아래 값에 결합됨.

- 요청 해시
- Agent DID
- 대상
- 승인자 DID
- 발급/만료 시각
- 승인자 서명

요청 인자가 바뀌거나 토큰이 만료/재사용되면 거부.

## 감사 원장

`SecurityGateway`는 실행 성공/실패를 전부 감사 이벤트로 기록함.

- canonical request hash
- response hash
- 이전 이벤트 hash
- 정책 결정과 사유
- Gateway DID
- Gateway Ed25519 서명
- Merkle root 배치

현재 기본 외부 앵커는 네트워크 게시를 안 하는 `DisabledExternalAnchorService`. 로컬 파일이나 S3 Object Lock 앵커 구현으로 교체 가능.

## 테스트와 공격 검증

전체 검증:

```bash
docker build -t agent-security-mcp .
```

현재 검증 결과:

```text
Java source files: 80
Tests run: 32
Failures: 0
Errors: 0
Docker build: SUCCESS
```

보안 테스트만 돌리려면:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -v maven-repository:/root/.m2 \
  -w /workspace \
  maven:3.9-eclipse-temurin-21 \
  mvn -B -ntp \
  -Dtest=DelegationVerifierTest,CommandIntegrityVerifierTest,SignedAuditLedgerTest \
  test
```

실제 재검증 결과 13개 테스트 전부 성공함.

| 공격 또는 검증 항목 | 결과 |
| --- | --- |
| 서명 후 위임 토큰 action 변조 | 차단 |
| 자식 Agent action 권한 확대 | 차단 |
| 자식 Agent resource 권한 확대 | 차단 |
| 부모보다 긴 만료시간 설정 | 차단 |
| 폐기된 위임 토큰 재사용 | 차단 |
| 신뢰하지 않는 root issuer | 차단 |
| 서명 후 명령 payload 변경 | 차단 |
| 다른 개인키로 만든 명령 서명 | 차단 |
| 감사 이벤트 hash chain | 검증 성공 |
| Gateway 서명 원장 | 검증 성공 |
| Merkle root 생성 | 검증 성공 |

## AWS로 확장(예정)

`infra/aws/main.tf`에 아래 실험용 리소스가 정의되어 있음.

- DynamoDB security state table
  - Challenge
  - `requestId`
  - 승인 토큰 사용 상태
  - 폐기 토큰
  - TTL 및 Point-in-Time Recovery
- DynamoDB audit table
- 비대칭 AWS KMS signing key
- Versioning과 Object Lock 활성화된 S3 anchor bucket

```bash
cd infra/aws
terraform init
terraform plan
```

> `terraform apply`는 실제 AWS 비용과 리소스 변경을 일으킴. 계정, Region, IAM 권한, 비용, 삭제 정책 확인 후 실행할 것.

## 현재 한계와 다음 작업

로컬 실험은 되지만 운영 배포 전에 더 채워야 함.

- 메모리 기반 Challenge, Replay, 폐기, 승인 상태를 Redis 또는 DynamoDB로 일원화
- 사용자/Agent 개인키를 AWS KMS, HSM, OS KeyStore 등으로 이전
- Gateway 임시 서명키를 영구 KMS 키로 교체
- 실제 사용자 승인 UI 또는 지갑 서명 클라이언트 구현
- OpenTimestamps 또는 S3 Object Lock 외부 앵커 운영 연결
- MCP `initialize`/`tools/call` 자동화하는 통합 클라이언트 작성
- TLS, JWT/OIDC, rate limit, 관측성, 장애 테스트 추가
- 위임 토큰을 JWS/JWT 또는 VC 표준으로 전환 검토
- 감사 원장 구현 경로를 하나의 운영 서비스로 통합


## 설계 원칙

> LLM의 주장을 믿지 않고 신원, 권한, 정책, 서명, 감사 증거로만 검증한다.
```