# William / Jarvis iOS Client Plan

**File:** `apps/worker_nodes/ios/ios_client_plan.md`  
**Component Name:** `IosClientPlan`  
**Agent/Module:** Device Worker Prompt Bible  
**Project:** William / Jarvis Multi-Agent AI SaaS System by Digital Promotix  
**Purpose:** iOS limitations and Shortcuts/API client design  
**Status:** Final production architecture plan

---

## 1. Executive Summary

The iOS worker node cannot operate like the Windows, macOS, Android, or browser workers because Apple restricts background automation, screen control, app control, accessibility automation, file access, notification access, and system-level actions.

For William/Jarvis, the iOS client must be designed as a **safe API client + Shortcuts bridge + approval-first mobile companion**.

The iOS client should support:

- User/workspace scoped login
- Device registration
- Heartbeat reporting
- Task polling
- Push/manual task approvals
- iOS Shortcuts execution handoff
- Deep link based actions
- Safe file picker upload
- Voice command capture
- Human-confirmed sensitive actions
- Security Agent approval gates
- Audit logging hooks
- Verification Agent result payloads
- Memory Agent compatible safe context
- Role/plan/subscription visibility checks
- Stop/resume controls

The iOS client must **not** claim to perform unrestricted background automation or full device control.

---

## 2. iOS Platform Reality Check

### 2.1 What iOS Allows

William/Jarvis iOS client can safely support:

| Capability | Supported | Design |
|---|---:|---|
| User login | Yes | SaaS API auth |
| Workspace switching | Yes | API-scoped context |
| Device registration | Yes | Register iPhone/iPad as worker node |
| Heartbeat | Yes | Foreground/background refresh where allowed |
| Task polling | Limited | Foreground, background refresh, push-triggered fetch |
| Push notifications | Yes | APNs/Firebase Cloud Messaging |
| Siri Shortcuts | Yes | App Intents / Shortcuts |
| Open URLs/deep links | Yes | Universal Links / custom URL schemes |
| File upload | Yes | Document picker |
| Photo upload | Yes | Photos picker with permission |
| Voice command capture | Yes | Microphone permission |
| Calendar/contact integration | Limited | Permission-based |
| Manual approval flows | Yes | In-app approve/deny UI |
| App-to-backend API client | Yes | HTTPS |
| Verification reports | Yes | API payloads |
| Audit logs | Yes | API payloads |
| Memory-safe context | Yes | Explicit user-approved context only |

---

### 2.2 What iOS Does Not Allow

William/Jarvis iOS client must not depend on:

| Restricted Capability | Reason |
|---|---|
| Full screen reading across apps | iOS sandboxing |
| Full background app automation | iOS background limits |
| Clicking buttons inside other apps | Not allowed outside Shortcuts / limited APIs |
| Reading all notifications | Not available to normal apps |
| Accessing SMS/iMessage contents | Not available to normal apps |
| Silent call control | Restricted |
| Silent file system scanning | Sandbox restriction |
| Full browser automation outside WebKit/Safari handoff | Platform limitation |
| Unapproved sensitive actions | William/Jarvis Security Agent rule |
| Cross-user task execution | SaaS isolation violation |

---

## 3. Required Architecture

The iOS worker should be implemented as:

```text
William iOS App
  ├── Auth Client
  ├── Workspace Context Manager
  ├── Device Registration Client
  ├── Heartbeat Client
  ├── Task Polling Client
  ├── Push Notification Receiver
  ├── Shortcuts / App Intents Bridge
  ├── Deep Link Router
  ├── Permission Manager
  ├── Security Approval UI
  ├── Safe Action Executor
  ├── Audit Reporter
  ├── Verification Reporter
  └── Memory Context Reporter 