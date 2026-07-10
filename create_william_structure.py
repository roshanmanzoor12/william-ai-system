#!/usr/bin/env python3
"""
William / Jarvis project scaffold creator.

Creates every folder and file path from the William/Jarvis All-File Prompt Bible.
Safety rule: existing files are NEVER overwritten or modified.

Usage from your project folder:
    python create_william_structure.py

Dry run:
    python create_william_structure.py --dry-run

Custom target folder:
    python create_william_structure.py --root C:/William-Jarvis
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

# (prompt_number, file_path, required_class_name, purpose)
FILE_SPECS: List[Tuple[int, str, str, str]] = [
    (1, 'main.py', 'MainApp', 'Application entry point that boots config, loads agents, starts CLI/API hooks, and runs a safe smoke test.'),
    (2, 'requirements.txt', 'No class required unless helpful; use functions/config/data structure appropriate for this file.', 'Python dependency list for core backend, agents, dashboard API, testing, and optional integrations.'),
    (3, '.env.example', 'No class required unless helpful; use functions/config/data structure appropriate for this file.', 'Safe environment variable template with no secrets, only placeholders and descriptions.'),
    (4, 'README.md', 'No class required unless helpful; use functions/config/data structure appropriate for this file.', 'Developer setup guide, architecture overview, run commands, build order, and safety rules.'),
    (5, 'core/context.py', 'TaskContext', 'Shared SaaS task context for user_id, workspace_id, role, plan, permissions, request_id, session_id, and trace metadata.'),
    (6, 'core/config.py', 'CoreConfig', 'Core configuration defaults for Master Agent, routing, timeouts, safe mode, logging, and environment loading.'),
    (7, 'core/master_agent.py', 'MasterAgent', 'Main Jarvis reporting brain that receives requests, recalls memory, plans tasks, routes agents, checks security, verifies results, saves memory, and reports final status.'),
    (8, 'core/planner.py', 'Planner', 'Breaks a user request into ordered task steps with agent intent, risk level, dependencies, and expected result.'),
    (9, 'core/router.py', 'Router', 'Routes planned tasks to the correct registered agent and handles multi-agent execution order.'),
    (10, 'core/task_manager.py', 'TaskManager', 'Tracks task lifecycle, statuses, progress, retries, failures, parent/child tasks, and user/workspace isolation.'),
    (11, 'core/response_builder.py', 'ResponseBuilder', 'Builds final user-facing progress reports, summaries, errors, completion percentages, and next steps.'),
    (12, 'core/safety_bridge.py', 'SafetyBridge', 'Bridge that sends sensitive task payloads to Security Agent before execution.'),
    (13, 'core/verification_bridge.py', 'VerificationBridge', 'Bridge that sends completed task payloads to Verification Agent for proof-based confirmation.'),
    (14, 'core/memory_bridge.py', 'MemoryBridge', 'Bridge that sends recall/save/update/forget requests to Memory Agent.'),
    (15, 'agents/base_agent.py', 'BaseAgent', 'Standard parent class for every William agent with structured task handling, SaaS context validation, permission metadata, health checks, result formatting, audit hooks, event hooks, verification hooks, memory payloads, and safe execution helpers.'),
    (16, 'agents/registry.py', 'AgentRegistry', 'Central registry that safely imports and registers all 14 agents plus future plugin agents.'),
    (17, 'agents/agent_loader.py', 'AgentLoader', 'Loads agent classes from registry, instantiates per user/workspace, and prevents broken imports from crashing the system.'),
    (18, 'agents/agent_router.py', 'AgentRouter', 'Agent-level router that maps intents to agents and supports fallback routing and multi-agent chains.'),
    (19, 'agents/agent_manifest.py', 'AgentManifest', 'Stores metadata, capabilities, versions, dependencies, status, and file counts for each agent.'),
    (20, 'agents/agent_permissions.py', 'AgentPermissions', 'Defines allowed, approval-required, and blocked actions per agent and routes sensitive actions to Security Agent.'),
    (21, 'agents/agent_events.py', 'AgentEvents', 'Event bus for agent-to-agent messages, task events, errors, completions, and audit hooks.'),
    (22, 'agents/agent_health.py', 'AgentHealth', 'Checks agent availability, dependencies, required files, permissions, and health status.'),
    (23, 'agents/agent_config.py', 'AgentSystemConfig', 'Global agent system configuration for safe mode, timeouts, dynamic loading, enabled agents, and verification settings.'),
    (24, 'agents/voice_agent/voice_agent.py', 'VoiceAgent', 'Main voice controller for wake word, STT, TTS, language detection, device streaming, and interruption.'),
    (25, 'agents/voice_agent/wake_word.py', 'WakeWordDetector', 'Detects William wake word, custom wake words, clap/tap activation, and gesture activation.'),
    (26, 'agents/voice_agent/stt_engine.py', 'STTEngine', 'Converts speech to text with multilingual, streaming, offline fallback, and correction support.'),
    (27, 'agents/voice_agent/tts_engine.py', 'TTSEngine', 'Converts text to natural speech with language voices, streaming, styles, volume, and interruption support.'),
    (28, 'agents/voice_agent/language_engine.py', 'LanguageEngine', 'Detects English, Roman Urdu, Urdu, Hindi, Arabic, mixed speech, and chooses reply language.'),
    (29, 'agents/voice_agent/device_stream.py', 'DeviceStream', 'Handles mic/speaker streams from mobile, desktop, smartwatch, glasses, Bluetooth, and remote devices.'),
    (30, 'agents/voice_agent/interruption.py', 'InterruptionHandler', 'Stops speaking when the user interrupts and captures the new command.'),
    (31, 'agents/voice_agent/voice_loop.py', 'VoiceLoop', 'Always-listening background loop with idle, active, conversation, private, and sleep modes.'),
    (32, 'agents/voice_agent/session_manager.py', 'VoiceSessionManager', 'Tracks active voice sessions, language, current topic, source device, and timeouts.'),
    (33, 'agents/voice_agent/audio_router.py', 'AudioRouter', 'Routes audio input/output across phone, laptop, earbuds, watch, glasses, and car Bluetooth.'),
    (34, 'agents/voice_agent/noise_control.py', 'NoiseControl', 'Noise suppression, echo cancellation, wind/crowd filtering, gain normalization.'),
    (35, 'agents/voice_agent/speaker_recognition.py', 'SpeakerRecognition', 'Owner/trusted speaker recognition and unknown voice blocking for sensitive tasks.'),
    (36, 'agents/voice_agent/emotion_detector.py', 'EmotionDetector', 'Detects urgency, stress, emotion, whispering, and adjusts response tone metadata.'),
    (37, 'agents/voice_agent/whisper_mode.py', 'WhisperMode', 'Private low-volume mode and text fallback for sensitive contexts.'),
    (38, 'agents/voice_agent/voice_profiles.py', 'VoiceProfiles', 'Stores user voice preferences, language style, speed, volume, and voice persona.'),
    (39, 'agents/voice_agent/voice_cloning.py', 'VoiceCloning', 'Consent-only custom voice cloning manager and protected voice model metadata.'),
    (40, 'agents/voice_agent/gesture_trigger.py', 'GestureTrigger', 'Detects clap, tap, smart glasses, and hand gesture triggers. William / Jarvis All-File Prompt Bible - Digital Promotix Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.'),
    (41, 'agents/voice_agent/conversation_mode.py', 'ConversationMode', 'Continuous real-time conversation mode after wake word with follow-up context.'),
    (42, 'agents/voice_agent/voice_memory.py', 'VoiceMemory', 'Memory bridge for voice preferences, recurring phrases, language behavior, and audio notes.'),
    (43, 'agents/voice_agent/config.py', 'VoiceConfig', 'Voice Agent settings, languages, wake word, engine choices, and privacy flags.'),
    (44, 'agents/system_agent/system_agent.py', 'SystemAgent', 'Main system controller for apps, files, OS commands, device settings, and automation with permission checks.'),
    (45, 'agents/system_agent/app_controller.py', 'AppController', 'Open, close, focus, switch, minimize, maximize, and restart apps safely.'),
    (46, 'agents/system_agent/file_manager.py', 'FileManager', 'Create, rename, move, copy, delete, backup, search, compress, and organize files/folders.'),
    (47, 'agents/system_agent/os_commands.py', 'OSCommands', 'Run safe OS commands, check processes, ports, system status, and services.'),
    (48, 'agents/system_agent/device_controls.py', 'DeviceControls', 'Control WiFi, Bluetooth, volume, brightness, battery saver, screen lock, sleep, restart, shutdown.'),
    (49, 'agents/system_agent/automation.py', 'SystemAutomation', 'Keyboard/mouse/gesture automation, clicking, typing, scrolling, hotkeys, and macros.'),
    (50, 'agents/system_agent/notification_reader.py', 'NotificationReader', 'Read and summarize notifications with permission and priority filtering.'),
    (51, 'agents/system_agent/message_controller.py', 'MessageController', 'Read/draft/send messages only with approval across WhatsApp, SMS, Gmail, Slack, etc.'),
    (52, 'agents/system_agent/call_controller.py', 'CallController', 'Detect, answer, reject, mute, dial, and log calls with strict approval.'),
    (53, 'agents/system_agent/permission_guard.py', 'SystemPermissionGuard', 'Local permission guard for System Agent risky actions before Security Agent.'),
    (54, 'agents/system_agent/app_profiles.py', 'AppProfiles', 'App-specific profiles for Chrome, VS Code, Photoshop, WhatsApp, banking apps, etc.'),
    (55, 'agents/system_agent/device_sync.py', 'DeviceSync', 'Multi-device routing and sync for laptop, phone, desktop, server, watch, glasses.'),
    (56, 'agents/system_agent/gesture_control.py', 'GestureControl', 'Hand/glass/tap/clap gestures mapped to safe system commands.'),
    (57, 'agents/system_agent/desktop_vision.py', 'DesktopVision', 'Screen OCR and UI detection bridge for errors, popups, windows, buttons.'),
    (58, 'agents/system_agent/task_recorder.py', 'TaskRecorder', 'Records manual workflows and turns them into safe replayable macros.'),
    (59, 'agents/system_agent/system_memory.py', 'SystemMemory', 'Remembers common folders, apps, device settings, and workflow preferences.'),
    (60, 'agents/system_agent/config.py', 'SystemConfig', 'System Agent permissions, safe mode, protected actions, and platform settings.'),
    (61, 'agents/browser_agent/browser_agent.py', 'BrowserAgent', 'Internet brain for search, website opening, scraping, page analysis, SEO and competitor research.'),
    (62, 'agents/browser_agent/search_engine.py', 'SearchEngine', 'Builds search queries, searches Google/Bing, filters/ranks results.'),
    (63, 'agents/browser_agent/scraper.py', 'Scraper', 'Fetches public pages and extracts visible data safely.'),
    (64, 'agents/browser_agent/page_analyzer.py', 'PageAnalyzer', 'Detects page type, offers, CTAs, trust signals, UX and conversion problems.'),
    (65, 'agents/browser_agent/multi_tab_planner.py', 'MultiTabPlanner', 'Plans and manages multi-tab research workspaces.'),
    (66, 'agents/browser_agent/automation.py', 'BrowserAutomation', 'Browser actions: open URLs, click, scroll, forms with approval, screenshots.'),
    (67, 'agents/browser_agent/browser_session.py', 'BrowserSession', 'Tracks tabs, visited URLs, cookies/session metadata, task state.'),
    (68, 'agents/browser_agent/tab_manager.py', 'TabManager', 'Open, close, switch, label, and organize browser tabs safely.'),
    (69, 'agents/browser_agent/content_extractor.py', 'ContentExtractor', 'Extract hero, headings, CTAs, pricing, testimonials, FAQs, links, tables.'),
    (70, 'agents/browser_agent/seo_analyzer.py', 'SEOAnalyzer', 'Analyze title, meta, headings, schema, links, alts, keywords, local SEO.'),
    (71, 'agents/browser_agent/competitor_analyzer.py', 'CompetitorAnalyzer', 'Compare websites, pricing, features, CTAs, trust, funnels, gaps.'),
    (72, 'agents/browser_agent/price_monitor.py', 'PriceMonitor', 'Track competitor pricing changes, discounts, features, and alerts.'),
    (73, 'agents/browser_agent/workflow_learner.py', 'BrowserWorkflowLearner', 'Learn website signup/checkout/dashboard flows step-by-step.'),
    (74, 'agents/browser_agent/form_handler.py', 'FormHandler', 'Detect, fill, validate forms with approval; never submit sensitive forms silently.'),
    (75, 'agents/browser_agent/download_manager.py', 'DownloadManager', 'Download public PDFs/reports/assets safely and organize them.'),
    (76, 'agents/browser_agent/screenshot_tool.py', 'BrowserScreenshotTool', 'Capture page/section screenshots for audits and proof.'),
    (77, 'agents/browser_agent/browser_memory.py', 'BrowserMemory', 'Save useful research findings, competitor notes, and source history.'),
    (78, 'agents/browser_agent/permissions.py', 'BrowserPermissions', 'Browser-specific permission rules for forms, logins, scraping, downloads.'),
    (79, 'agents/browser_agent/config.py', 'BrowserConfig', 'Browser Agent settings: max tabs, engines, rate limits, screenshots, safe mode.'),
    (80, 'agents/code_agent/code_agent.py', 'CodeAgent', 'Builder AI for project creation, code writing/editing, command running, debugging, testing, and deployment support.'),
    (81, 'agents/code_agent/project_builder.py', 'ProjectBuilder', 'Creates full project architecture and folder structures.'),
    (82, 'agents/code_agent/file_generator.py', 'FileGenerator', 'Creates files, templates, configs, components, and docs.'),
    (83, 'agents/code_agent/code_writer.py', 'CodeWriter', 'Writes new production code files, classes, functions, APIs, components.'),
    (84, 'agents/code_agent/code_editor.py', 'CodeEditor', 'Safely modifies existing files, patches blocks, preserves structure.'),
    (85, 'agents/code_agent/terminal_runner.py', 'TerminalRunner', 'Runs safe commands, servers, installs, builds, tests with permission.'),
    (86, 'agents/code_agent/project_analyzer.py', 'ProjectAnalyzer', 'Reads project structure, detects framework, dependencies, risks, missing files.'),
    (87, 'agents/code_agent/dependency_manager.py', 'DependencyManager', 'Manages packages, version conflicts, requirements, package files.'),
    (88, 'agents/code_agent/error_analyzer.py', 'ErrorAnalyzer', 'Analyzes tracebacks, logs, build errors, CORS/OAuth/API errors.'),
    (89, 'agents/code_agent/self_debugger.py', 'SelfDebugger', 'Runs debug cycle: analyze, patch, rerun, verify, stop after limit.'),
    (90, 'agents/code_agent/test_runner.py', 'TestRunner', 'Runs/generates tests, endpoint checks, build checks, smoke tests.'),
    (91, 'agents/code_agent/git_manager.py', 'GitManager', 'Git status, diff, branch, commit, rollback with approval.'),
    (92, 'agents/code_agent/ci_cd_manager.py', 'CICDManager', 'CI/CD, Docker, GitHub Actions, VPS deploy, Nginx/Gunicorn/SSL.'),
    (93, 'agents/code_agent/api_builder.py', 'APIBuilder', 'Generates REST APIs, auth, CRUD, webhooks, Flask/FastAPI routers.'),
    (94, 'agents/code_agent/frontend_builder.py', 'FrontendBuilder', 'Builds React/Next/Flutter screens, dashboards, forms, components.'),
    (95, 'agents/code_agent/database_builder.py', 'DatabaseBuilder', 'Creates models, migrations, schemas, relationships, indexes, seed data.'),
    (96, 'agents/code_agent/security_checker.py', 'SecurityChecker', 'Scans code for secrets, injection risks, unsafe commands, weak access.'),
    (97, 'agents/code_agent/documentation_writer.py', 'DocumentationWriter', 'Writes README, setup, API docs, deployment, changelog, troubleshooting.'),
    (98, 'agents/code_agent/code_memory.py', 'CodeMemory', 'Remembers project rules, architecture, file roles, naming, prior fixes.'),
    (99, 'agents/code_agent/config.py', 'CodeConfig', 'Code Agent safe mode, backup rules, terminal/deploy/git permission settings.'),
    (100, 'agents/memory_agent/memory_agent.py', 'MemoryAgent', 'AI memory brain for short-term memory, long-term memory, project/client memory, embeddings, recall, and privacy.'),
    (101, 'agents/memory_agent/short_term.py', 'ShortTermMemory', 'Current session context, active task, active agent, recent commands.'),
    (102, 'agents/memory_agent/long_term.py', 'LongTermMemory', 'Permanent useful facts, preferences, project rules, business context.'),
    (103, 'agents/memory_agent/embeddings.py', 'EmbeddingEngine', 'Chunking, embedding creation, vector storage, semantic search.'),
    (104, 'agents/memory_agent/recall_engine.py', 'RecallEngine', 'Keyword/semantic/project/client/time recall and ranking.'),
    (105, 'agents/memory_agent/memory_router.py', 'MemoryRouter', 'Decides category, importance, privacy level, and storage layer.'),
    (106, 'agents/memory_agent/memory_cleaner.py', 'MemoryCleaner', 'Deduplicates, merges, marks outdated, cleans noisy memories.'),
    (107, 'agents/memory_agent/memory_summarizer.py', 'MemorySummarizer', 'Compresses long chats/docs/project updates into clean memory.'),
    (108, 'agents/memory_agent/preference_manager.py', 'PreferenceManager', 'Stores answer style, code format, design, brand, language preferences.'),
    (109, 'agents/memory_agent/project_memory.py', 'ProjectMemory', 'Stores project architecture, file roles, bugs, endpoints, decisions.'),
    (110, 'agents/memory_agent/client_memory.py', 'ClientMemory', 'Stores client/business notes, proposals, campaigns, deadlines.'),
    (111, 'agents/memory_agent/team_memory.py', 'TeamMemory', 'Shared workspace memory with role-based access.'),
    (112, 'agents/memory_agent/knowledge_graph.py', 'KnowledgeGraph', 'Nodes/edges connecting users, projects, files, agents, tasks, decisions.'),
    (113, 'agents/memory_agent/privacy_guard.py', 'MemoryPrivacyGuard', 'Blocks sensitive memory storage, approval flows, forget/export controls.'),
    (114, 'agents/memory_agent/memory_search.py', 'MemorySearch', 'Unified keyword + semantic search by project/client/agent/date.'),
    (115, 'agents/memory_agent/memory_backup.py', 'MemoryBackup', 'Export/import/snapshot/restore memory database safely.'),
    (116, 'agents/memory_agent/memory_sync.py', 'MemorySync', 'Sync memory across devices/workspaces with conflict resolution.'),
    (117, 'agents/memory_agent/config.py', 'MemoryConfig', 'Memory retention, privacy, vector settings, cleanup and backup settings.'),
    (118, 'agents/security_agent/security_agent.py', 'SecurityAgent', 'Protection brain for permission checks, risk scoring, approvals, biometrics, audit logs, and fraud detection.'),
    (119, 'agents/security_agent/permission_checker.py', 'PermissionChecker', 'Checks if action is allowed, confirm-required, biometric-required, or blocked.'),
    (120, 'agents/security_agent/biometric_gate.py', 'BiometricGate', 'Face/fingerprint/voice/PIN/trusted-device verification layer.'),
    (121, 'agents/security_agent/risk_engine.py', 'RiskEngine', 'Scores risks for financial, destructive, private, device, terminal, and account actions.'),
    (122, 'agents/security_agent/audit_logger.py', 'AuditLogger', 'Logs sensitive requests, approvals, denials, blocks, biometric attempts, reports.'),
    (123, 'agents/security_agent/action_classifier.py', 'ActionClassifier', 'Classifies action type, resource, source agent, sensitivity, permission level.'),
    (124, 'agents/security_agent/approval_manager.py', 'ApprovalManager', 'Creates user confirmation prompts and records approvals/denials.'),
    (125, 'agents/security_agent/fraud_detector.py', 'FraudDetector', 'Detects scams, phishing, fake login pages, suspicious invoices, payment fraud.'),
    (126, 'agents/security_agent/anomaly_detector.py', 'AnomalyDetector', 'Detects unusual devices, voices, command patterns, failed attempts, mass exports.'),
    (127, 'agents/security_agent/device_access.py', 'DeviceAccess', 'Trusted devices, unknown device blocking, device permissions.'),
    (128, 'agents/security_agent/file_protection.py', 'FileProtection', 'Protects folders/files from accidental deletion and creates backups before risk.'),
    (129, 'agents/security_agent/payment_guard.py', 'PaymentGuard', 'Protects payments, banking, purchases, transfers; never auto-pays.'),
    (130, 'agents/security_agent/app_lock.py', 'AppLock', 'Locks sensitive apps behind verification.'),
    (131, 'agents/security_agent/session_guard.py', 'SessionGuard', 'Session timeout, re-authentication, unknown device/session protection.'),
    (132, 'agents/security_agent/privacy_guard.py', 'SecurityPrivacyGuard', 'Protects private messages, files, screenshots, secrets, logs.'),
    (133, 'agents/security_agent/threat_monitor.py', 'ThreatMonitor', 'Detects suspicious processes, scripts, downloads, browser extensions, network behavior.'),
    (134, 'agents/security_agent/policy_engine.py', 'PolicyEngine', 'Central policy engine applied across all agents.'),
    (135, 'agents/security_agent/emergency_lock.py', 'EmergencyLock', 'Kill switch to stop all agents, freeze automation, lock sensitive apps.'),
    (136, 'agents/security_agent/config.py', 'SecurityConfig', 'Security thresholds, protected folders, blocked commands, biometric flags.'),
    (137, 'agents/verification_agent/verification_agent.py', 'VerificationAgent', 'Task confirmation brain for app/file/browser/device/code state checking, screenshots, validation, and proof reports.'),
    (138, 'agents/verification_agent/state_checker.py', 'StateChecker', 'Checks process, window, file, folder, service, port, device setting states.'),
    (139, 'agents/verification_agent/screenshot_checker.py', 'ScreenshotChecker', 'Captures/analyzes screens for app, page, UI, popup, error confirmation.'),
    (140, 'agents/verification_agent/result_validator.py', 'ResultValidator', 'Compares expected vs actual result and returns status/confidence.'),
    (141, 'agents/verification_agent/app_state_checker.py', 'AppStateChecker', 'Confirms app opened, closed, focused, ready, crashed.'),
    (142, 'agents/verification_agent/file_state_checker.py', 'FileStateChecker', 'Confirms files/folders created, moved, modified, backups, deletions.'),
    (143, 'agents/verification_agent/browser_state_checker.py', 'BrowserStateChecker', 'Confirms browser opened, tab exists, URL/page title/content loaded, no errors.'),
    (144, 'agents/verification_agent/code_state_checker.py', 'CodeStateChecker', 'Confirms code edits, syntax, builds, tests, servers, endpoints.'),
    (145, 'agents/verification_agent/device_state_checker.py', 'DeviceStateChecker', 'Confirms WiFi, Bluetooth, volume, brightness, battery, screen lock.'),
    (146, 'agents/verification_agent/ui_element_checker.py', 'UIElementChecker', 'Confirms buttons, inputs, modals, forms, toasts, progress bars visible.'),
    (147, 'agents/verification_agent/action_replay_checker.py', 'ActionReplayChecker', 'Checks multi-step automation and identifies failed step. William / Jarvis All-File Prompt Bible - Digital Promotix Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.'),
    (148, 'agents/verification_agent/error_detector.py', 'VerificationErrorDetector', 'Detects app crashes, 404/500, permission denied, timeouts, build failures.'),
    (149, 'agents/verification_agent/proof_collector.py', 'ProofCollector', 'Collects screenshots, logs, process status, API responses, timestamps.'),
    (150, 'agents/verification_agent/retry_manager.py', 'RetryManager', 'Retries safe failed tasks and stops risky/infinite retries. William / Jarvis All-File Prompt Bible - Digital Promotix Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.'),
    (151, 'agents/verification_agent/report_generator.py', 'VerificationReportGenerator', 'Creates task completion reports with proof, confidence, next actions.'),
    (152, 'agents/verification_agent/verification_memory.py', 'VerificationMemory', 'Stores success signals and verification patterns for apps/sites/projects.'),
    (153, 'agents/verification_agent/config.py', 'VerificationConfig', 'Verification thresholds, screenshot rules, retry settings, safe mode.'),
    (154, 'agents/visual_agent/visual_agent.py', 'VisualAgent', 'Screen and vision brain for screenshots, videos, OCR, UI mapping, element detection, and privacy filtering.'),
    (155, 'agents/visual_agent/screenshot_reader.py', 'ScreenshotReader', 'Reads screenshots, detects app/page/screen, important text, buttons, errors.'),
    (156, 'agents/visual_agent/video_analyzer.py', 'VideoAnalyzer', 'Analyzes videos/screen recordings, extracts key frames and workflow steps.'),
    (157, 'agents/visual_agent/ocr_engine.py', 'OCREngine', 'Extracts and cleans text from screenshots/images/video frames.'),
    (158, 'agents/visual_agent/ui_mapper.py', 'UIMapper', 'Maps UI elements, hierarchy, clickable areas, cards, tables, menus.'),
    (159, 'agents/visual_agent/image_analyzer.py', 'ImageAnalyzer', 'Analyzes images, objects, layouts, design, lighting, creative assets.'),
    (160, 'agents/visual_agent/screen_context.py', 'ScreenContext', 'Detects current screen/app/page/workflow context.'),
    (161, 'agents/visual_agent/element_detector.py', 'ElementDetector', 'Finds buttons, inputs, cards, icons, labels, bounds, confidence.'),
    (162, 'agents/visual_agent/workflow_learner.py', 'VisualWorkflowLearner', 'Learns workflows from visual steps and produces automation recipes.'),
    (163, 'agents/visual_agent/visual_memory.py', 'VisualMemory', 'Stores repeated screen patterns, app layouts, error screens, UI positions.'),
    (164, 'agents/visual_agent/error_screen_detector.py', 'ErrorScreenDetector', 'Detects visual errors and sends structured issue to proper agent.'),
    (165, 'agents/visual_agent/form_reader.py', 'FormReader', 'Reads forms, labels, required fields, validation errors, submit controls.'),
    (166, 'agents/visual_agent/app_screen_mapper.py', 'AppScreenMapper', 'Known app-specific screen maps for Chrome, VS Code, WordPress, Google Ads, etc.'),
    (167, 'agents/visual_agent/video_frame_extractor.py', 'VideoFrameExtractor', 'Extracts important frames, removes duplicates, detects screen changes.'),
    (168, 'agents/visual_agent/visual_validator.py', 'VisualValidator', 'Compares expected vs actual screens for visual task validation.'),
    (169, 'agents/visual_agent/privacy_filter.py', 'PrivacyFilter', 'Redacts sensitive visual data and blocks hidden/private captures.'),
    (170, 'agents/visual_agent/annotation_tool.py', 'AnnotationTool', 'Draws boxes/labels around elements, errors, click targets for reports/debugging. William / Jarvis All-File Prompt Bible - Digital Promotix Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.'),
    (171, 'agents/visual_agent/config.py', 'VisualConfig', 'OCR/UI thresholds, video limits, redaction and screenshot privacy settings.'),
    (172, 'agents/workflow_agent/workflow_agent.py', 'WorkflowAgent', 'Automation pipeline brain for n8n, triggers, webhooks, Form->Sheet->WhatsApp->CRM, conditions, monitoring.'),
    (173, 'agents/workflow_agent/n8n_connector.py', 'N8NConnector', 'Connects to n8n, creates/activates workflows, manages nodes and executions.'),
    (174, 'agents/workflow_agent/workflow_builder.py', 'WorkflowBuilder', 'Builds trigger-action-condition-output pipelines and workflow JSON/configs.'),
    (175, 'agents/workflow_agent/trigger_engine.py', 'TriggerEngine', 'Starts workflows from forms, webhooks, sheets, email, schedule, manual command.'),
    (176, 'agents/workflow_agent/action_router.py', 'WorkflowActionRouter', 'Routes workflow steps to connectors or agents.'),
    (177, 'agents/workflow_agent/app_connector.py', 'AppConnector', 'Manages external app/API connectors and secure integration configs.'),
    (178, 'agents/workflow_agent/webhook_manager.py', 'WebhookManager', 'Creates/validates/routes webhook payloads.'),
    (179, 'agents/workflow_agent/form_pipeline.py', 'FormPipeline', 'Handles Form->Validate->Sheet->WhatsApp->CRM->Email->Follow-up.'),
    (180, 'agents/workflow_agent/crm_connector.py', 'CRMConnector', 'Creates/updates CRM contacts, deals, tags, notes, tasks, pipeline stages.'),
    (181, 'agents/workflow_agent/sheet_connector.py', 'SheetConnector', 'Reads/writes Google Sheets/Airtable/Excel rows, duplicate checks, exports.'),
    (182, 'agents/workflow_agent/whatsapp_connector.py', 'WhatsAppConnector', 'Sends approved WhatsApp internal alerts/templates with permission.'),
    (183, 'agents/workflow_agent/email_connector.py', 'EmailConnector', 'Sends approved emails, auto-replies, follow-ups, reports.'),
    (184, 'agents/workflow_agent/notification_engine.py', 'NotificationEngine', 'Sends alerts over WhatsApp/email/Slack/Discord/mobile/dashboard.'),
    (185, 'agents/workflow_agent/condition_engine.py', 'ConditionEngine', 'If/else rules, filtering, lead scoring, duplicate/spam checks, routing.'),
    (186, 'agents/workflow_agent/scheduler.py', 'WorkflowScheduler', 'Runs recurring/time-based workflows and delayed actions.'),
    (187, 'agents/workflow_agent/workflow_monitor.py', 'WorkflowMonitor', 'Tracks workflow runs, step status, failures, analytics.'),
    (188, 'agents/workflow_agent/retry_handler.py', 'RetryHandler', 'Retries safe failed steps without duplicate leads/messages.'),
    (189, 'agents/workflow_agent/workflow_templates.py', 'WorkflowTemplates', 'Reusable automation templates for leads, reports, support, reminders.'),
    (190, 'agents/workflow_agent/workflow_memory.py', 'WorkflowMemory', 'Stores workflow preferences, mappings, connected tools, templates.'),
    (191, 'agents/workflow_agent/approval_gate.py', 'ApprovalGate', 'Blocks sensitive workflow steps until Security Agent/user approval.'),
    (192, 'agents/workflow_agent/config.py', 'WorkflowConfig', 'Workflow settings, n8n, webhooks, retries, approvals, anti-spam.'),
    (193, 'agents/super_agents/hologram_agent/hologram_agent.py', 'HologramAgent', 'Main AR/hologram controller for glasses, overlays, gestures, spatial context.'),
    (194, 'agents/super_agents/hologram_agent/ar_overlay.py', 'AROverlay', 'Displays floating UI cards, notifications, instructions, and real-world overlays.'),
    (195, 'agents/super_agents/hologram_agent/spatial_mapper.py', 'SpatialMapper', 'Maps physical spaces, objects, and coordinates for AR interactions.'),
    (196, 'agents/super_agents/hologram_agent/gesture_bridge.py', 'GestureBridge', 'Maps hand/glasses gestures to safe William commands.'),
    (197, 'agents/super_agents/hologram_agent/real_world_context.py', 'RealWorldContext', 'Understands environment context and routes real-world tasks.'),
    (198, 'agents/super_agents/hologram_agent/object_recognizer.py', 'ObjectRecognizer', 'Detects physical objects and returns labels/confidence/context.'),
    (199, 'agents/super_agents/hologram_agent/navigation_overlay.py', 'NavigationOverlay', 'Shows path/direction/instruction overlays.'),
    (200, 'agents/super_agents/hologram_agent/notification_overlay.py', 'NotificationOverlay', 'Shows safe notifications and hides private data in public mode.'),
    (201, 'agents/super_agents/hologram_agent/device_bridge.py', 'HologramDeviceBridge', 'Connects glasses/watch/phone/laptop streams and controls.'),
    (202, 'agents/super_agents/hologram_agent/hologram_memory.py', 'HologramMemory', 'Stores AR layout preferences, safe zones, recurring overlays.'),
    (203, 'agents/super_agents/hologram_agent/config.py', 'HologramConfig', 'AR device settings, privacy flags, gesture settings, overlay limits.'),
    (204, 'agents/super_agents/call_agent/call_agent.py', 'CallAgent', 'Main call controller for receptionist mode, summaries, booking, lead qualification.'),
    (205, 'agents/super_agents/call_agent/call_listener.py', 'CallListener', 'Detects incoming/outgoing calls and permissions.'),
    (206, 'agents/super_agents/call_agent/receptionist_mode.py', 'ReceptionistMode', 'Business greeting, caller intake, routing, scripts.'),
    (207, 'agents/super_agents/call_agent/call_transcriber.py', 'CallTranscriber', 'Permission-based call STT/transcription and live note taking.'),
    (208, 'agents/super_agents/call_agent/call_summarizer.py', 'CallSummarizer', 'Summarizes calls, action items, sentiment, next steps.'),
    (209, 'agents/super_agents/call_agent/contact_router.py', 'ContactRouter', 'Routes callers to owner/team/CRM/support based on intent.'),
    (210, 'agents/super_agents/call_agent/voicemail_handler.py', 'VoicemailHandler', 'Handles voicemail, missed-call notes, callback reminders.'),
    (211, 'agents/super_agents/call_agent/appointment_booker.py', 'AppointmentBooker', 'Books meetings with calendar integration and confirmations.'),
    (212, 'agents/super_agents/call_agent/lead_qualifier.py', 'LeadQualifier', 'Qualifies caller budget, service, urgency, contact details.'),
    (213, 'agents/super_agents/call_agent/call_scripts.py', 'CallScripts', 'Sales/support/reception scripts and objection handling.'),
    (214, 'agents/super_agents/call_agent/call_memory.py', 'CallMemory', 'Stores approved call notes, preferences, leads, and summaries.'),
    (215, 'agents/super_agents/call_agent/config.py', 'CallConfig', 'Call settings, recording permissions, auto-answer flags, legal safety.'),
    (216, 'agents/super_agents/business_agent/business_agent.py', 'BusinessAgent', 'Main business controller for CRM, leads, analytics, clients, reports.'),
    (217, 'agents/super_agents/business_agent/crm_manager.py', 'CRMManager', 'Manage contacts, deals, pipelines, tags, notes, and stages.'),
    (218, 'agents/super_agents/business_agent/lead_tracker.py', 'LeadTracker', 'Tracks leads from forms, calls, ads, SEO, workflows, imports.'),
    (219, 'agents/super_agents/business_agent/analytics_engine.py', 'AnalyticsEngine', 'Calculates KPIs, trends, conversion rates, lead sources, revenue.'),
    (220, 'agents/super_agents/business_agent/client_manager.py', 'ClientManager', 'Manages client records, projects, status, deliverables, notes.'),
    (221, 'agents/super_agents/business_agent/sales_pipeline.py', 'SalesPipeline', 'Sales stages, follow-up tasks, hot/cold scoring, next actions.'),
    (222, 'agents/super_agents/business_agent/campaign_tracker.py', 'CampaignTracker', 'Tracks Google Ads, SEO, social, landing page campaign performance.'),
    (223, 'agents/super_agents/business_agent/revenue_tracker.py', 'RevenueTracker', 'Tracks revenue, invoices, paid/unpaid, MRR, pipeline value.'),
    (224, 'agents/super_agents/business_agent/report_builder.py', 'BusinessReportBuilder', 'Builds business reports, client reports, weekly summaries.'),
    (225, 'agents/super_agents/business_agent/task_manager.py', 'BusinessTaskManager', 'Business tasks, reminders, assignment, deadlines, status.'),
    (226, 'agents/super_agents/business_agent/business_memory.py', 'BusinessMemory', 'Stores business preferences, CRM rules, recurring reports.'),
    (227, 'agents/super_agents/business_agent/config.py', 'BusinessConfig', 'Business Agent settings, CRM provider configs, report periods, role rules.'),
    (228, 'agents/super_agents/finance_agent/finance_agent.py', 'FinanceAgent', 'Safe finance preparation brain for invoices, budgets, receipts, transaction drafts, never auto-transfer.'),
    (229, 'agents/super_agents/finance_agent/invoice_manager.py', 'InvoiceManager', 'Creates, tracks, updates invoices and reminders.'),
    (230, 'agents/super_agents/finance_agent/transaction_preparer.py', 'TransactionPreparer', 'Prepares transaction drafts only; never submits transfer.'),
    (231, 'agents/super_agents/finance_agent/budget_tracker.py', 'BudgetTracker', 'Tracks budgets, categories, limits, burn rates.'),
    (232, 'agents/super_agents/finance_agent/payment_guard.py', 'FinancePaymentGuard', 'Finance-specific payment safety and Security Agent handoff.'),
    (233, 'agents/super_agents/finance_agent/finance_reports.py', 'FinanceReports', 'Revenue, expenses, cash flow, profit/loss, subscription reports.'),
    (234, 'agents/super_agents/finance_agent/receipt_reader.py', 'ReceiptReader', 'OCR/parse receipts and invoice documents with privacy.'),
    (235, 'agents/super_agents/finance_agent/tax_helper.py', 'TaxHelper', 'Categorizes tax-related records and preparation summaries.'),
    (236, 'agents/super_agents/finance_agent/subscription_tracker.py', 'SubscriptionTracker', 'Tracks SaaS subscriptions, renewals, invoices, cancellation reminders.'),
    (237, 'agents/super_agents/finance_agent/expense_categorizer.py', 'ExpenseCategorizer', 'Categorizes expenses, duplicates, merchants, notes.'),
    (238, 'agents/super_agents/finance_agent/finance_memory.py', 'FinanceMemory', 'Stores safe finance preferences and approved recurring rules.'),
    (239, 'agents/super_agents/finance_agent/config.py', 'FinanceConfig', 'Finance safe-mode settings, blocked actions, approval thresholds.'),
    (240, 'agents/super_agents/creator_agent/creator_agent.py', 'CreatorAgent', 'Content and video production brain for scripts, VEO prompts, editing plans, captions, thumbnails, and content calendars.'),
    (241, 'agents/super_agents/creator_agent/video_editor.py', 'VideoEditor', 'Video editing plans, cuts, timing, b-roll, retention pattern breaks.'),
    (242, 'agents/super_agents/creator_agent/content_planner.py', 'ContentPlanner', 'Content calendar, topics, platform plans, campaigns, scheduling.'),
    (243, 'agents/super_agents/creator_agent/script_writer.py', 'ScriptWriter', 'Ad scripts, shorts scripts, dialogue, hooks, CTAs, voiceover.'),
    (244, 'agents/super_agents/creator_agent/thumbnail_designer.py', 'ThumbnailDesigner', 'Thumbnail concepts, text, composition, prompt ideas.'),
    (245, 'agents/super_agents/creator_agent/asset_manager.py', 'AssetManager', 'Organizes images, videos, audio, brand assets, references.'),
    (246, 'agents/super_agents/creator_agent/voiceover_builder.py', 'VoiceoverBuilder', 'Voiceover timing, tone, line splits, scene narration.'),
    (247, 'agents/super_agents/creator_agent/caption_generator.py', 'CaptionGenerator', 'Captions, subtitles, social post captions, hooks.'),
    (248, 'agents/super_agents/creator_agent/short_form_editor.py', 'ShortFormEditor', 'Reels/Shorts/TikTok pacing, retention, cuts, pattern breaks.'),
    (249, 'agents/super_agents/creator_agent/veo_prompt_builder.py', 'VeoPromptBuilder', 'VEO 3 cinematic prompts, JSON prompts, character continuity, scene specs.'),
    (250, 'agents/super_agents/creator_agent/brand_style.py', 'BrandStyle', 'Brand tone, style rules, colors, format, reusable creative guidelines.'),
    (251, 'agents/super_agents/creator_agent/config.py', 'CreatorConfig', 'Creator settings, platforms, durations, approval before publishing.'),
    (252, 'database/db.py', 'DatabaseManager', 'Database connection/session factory, engine setup, health check, migration compatibility.'),
    (253, 'database/models/user.py', 'UserModel', 'User model with auth identity, workspace relation, role, status, plan hooks.'),
    (254, 'database/models/workspace.py', 'WorkspaceModel', 'Workspace/tenant model for SaaS data isolation.'),
    (255, 'database/models/agent.py', 'AgentModels', 'Agent registry/session/task/event/health/error models.'),
    (256, 'database/models/memory.py', 'MemoryModels', 'Short/long/project/client/team/vector/knowledge graph memory models.'),
    (257, 'database/models/security.py', 'SecurityModels', 'Audit logs, approvals, risk decisions, permission events.'),
    (258, 'database/models/subscription.py', 'SubscriptionModels', 'Plans, subscriptions, usage limits, user_agent_access models.'),
    (259, 'database/models/business.py', 'BusinessModels', 'Clients, leads, CRM contacts/deals, campaigns, reports, workflows, calls, invoices, content projects.'),
    (260, 'apps/api/main.py', 'APIApp', 'API entry point with app creation, middleware, routers, health checks.'),
    (261, 'apps/api/auth_routes.py', 'AuthRoutes', 'Login/register/logout/token/refresh routes with workspace and role context.'),
    (262, 'apps/api/agent_routes.py', 'AgentRoutes', 'Run agent tasks, list agents, agent health, task history routes.'),
    (263, 'apps/api/memory_routes.py', 'MemoryRoutes', 'Memory save/recall/search/forget/export routes with privacy rules.'),
    (264, 'apps/api/security_routes.py', 'SecurityRoutes', 'Approvals, audit logs, risk checks, policies, emergency lock routes.'),
    (265, 'apps/api/subscription_routes.py', 'SubscriptionRoutes', 'Plans, subscriptions, usage, billing state, access checks routes.'),
    (266, 'apps/api/dashboard_routes.py', 'DashboardRoutes', 'Dashboard analytics, task summaries, user stats, reports.'),
    (267, 'apps/api/websocket_routes.py', 'WebSocketRoutes', 'Realtime task progress, agent events, notifications via WebSocket.'),
    (268, 'apps/dashboard/package.json', 'No class required unless helpful; use functions/config/data structure appropriate for this file.', 'Dashboard dependencies, scripts, build/dev commands.'),
    (269, 'apps/dashboard/src/app/layout.tsx', 'DashboardLayout', 'Main dashboard layout with auth shell, sidebar, topbar, theme.'),
    (270, 'apps/dashboard/src/app/page.tsx', 'AIConsolePage', 'Main AI Console page for asking William and viewing task progress.'),
    (271, 'apps/dashboard/src/app/agents/page.tsx', 'AgentsPage', 'Agent Control Center page with enable/disable, access, health, usage.'),
    (272, 'apps/dashboard/src/app/memory/page.tsx', 'MemoryPage', 'Memory Manager page with search, project/client memories, privacy controls.'),
    (273, 'apps/dashboard/src/app/tasks/page.tsx', 'TasksPage', 'Task history, status, logs, proof, retry/request approval UI.'),
    (274, 'apps/dashboard/src/app/security/page.tsx', 'SecurityPage', 'Security audit logs, approvals, risk events, emergency lock UI.'),
    (275, 'apps/dashboard/src/app/billing/page.tsx', 'BillingPage', 'Plans, subscription, usage limits, invoices, access restrictions.'),
    (276, 'apps/dashboard/src/app/settings/page.tsx', 'SettingsPage', 'Workspace, team, roles, agent permissions, integrations settings.'),
    (277, 'subscriptions/plan_rules.py', 'PlanRules', 'Plan definitions, allowed agents, usage limits, feature gates.'),
    (278, 'subscriptions/billing_manager.py', 'BillingManager', 'Billing status, invoices, payment provider abstraction, safe payment rules.'),
    (279, 'subscriptions/usage_meter.py', 'UsageMeter', 'Counts tasks, tokens, agent runs, workflows, storage, per user/workspace.'),
    (280, 'subscriptions/access_control.py', 'AccessControl', 'Checks plan, role, user_agent_access before agent execution.'),
    (281, 'security/secrets_manager.py', 'SecretsManager', 'Reads secrets from environment/secret stores safely; never hardcodes values.'),
    (282, 'security/encryption.py', 'EncryptionManager', 'Encryption/decryption helpers for sensitive stored data with safe key handling.'),
    (283, 'security/policies/default_policy.json', 'No class required unless helpful; use functions/config/data structure appropriate for this file.', 'Default global policy rules for blocked/sensitive/allowed actions.')
]

NO_CLASS_MARKERS = (
    "No class required",
    "NoClassRequired",
)


def normalize_path(path_value: str) -> str:
    """Normalize PDF path text into a safe relative project path."""
    path_value = path_value.strip().replace("\\", "/")
    while "//" in path_value:
        path_value = path_value.replace("//", "/")
    if path_value.startswith("/") or ":" in path_value:
        raise ValueError(f"Unsafe absolute path is not allowed: {path_value!r}")
    if any(part in ("..", "") for part in Path(path_value).parts):
        raise ValueError(f"Unsafe relative path is not allowed: {path_value!r}")
    return path_value


def class_name_allowed(required_class_name: str) -> bool:
    return bool(required_class_name) and not any(
        marker.lower() in required_class_name.lower() for marker in NO_CLASS_MARKERS
    )


def python_stub(path_value: str, required_class_name: str, purpose: str, prompt_number: int) -> str:
    """Return an import-safe Python starter file for a missing file."""
    if class_name_allowed(required_class_name):
        return (
            f'"""\n{purpose}\n\n'
            f'Scaffolded from William / Jarvis All-File Prompt Bible prompt {prompt_number}.\n'
            f'Replace this stub with the full generated production file when ready.\n'
            f'"""\n\n'
            f'from __future__ import annotations\n\n\n'
            f'class {required_class_name}:\n'
            f'    """Starter class for {path_value}."""\n\n'
            f'    def __init__(self, *args, **kwargs) -> None:\n'
            f'        self.args = args\n'
            f'        self.kwargs = kwargs\n\n'
            f'    def health_check(self) -> dict:\n'
            f'        """Return a simple import-safe health response until full code is generated."""\n'
            f'        return {{\n'
            f'            "success": True,\n'
            f'            "message": "{required_class_name} scaffold exists. Replace with full implementation.",\n'
            f'            "data": {{"file": "{path_value}", "prompt_number": {prompt_number}}},\n'
            f'            "error": None,\n'
            f'            "metadata": {{"scaffold": True}},\n'
            f'        }}\n'
        )
    return (
        f'"""\n{purpose}\n\n'
        f'Scaffolded from William / Jarvis All-File Prompt Bible prompt {prompt_number}.\n'
        f'Replace this stub with the full generated production file when ready.\n'
        f'"""\n\n'
        f'from __future__ import annotations\n\n\n'
        f'def health_check() -> dict:\n'
        f'    """Return a simple import-safe health response until full code is generated."""\n'
        f'    return {{\n'
        f'        "success": True,\n'
        f'        "message": "Scaffold exists. Replace with full implementation.",\n'
        f'        "data": {{"file": "{path_value}", "prompt_number": {prompt_number}}},\n'
        f'        "error": None,\n'
        f'        "metadata": {{"scaffold": True}},\n'
        f'    }}\n'
    )


def text_stub(path_value: str, purpose: str, prompt_number: int) -> str:
    name = Path(path_value).name.lower()
    if name == "requirements.txt":
        return "# William / Jarvis requirements scaffold. Add packages as each module is implemented.\n"
    if name == ".env.example":
        return "# William / Jarvis safe environment template. Do not put real secrets here.\nAPP_ENV=development\nSAFE_MODE=true\n"
    if name == "readme.md":
        return f"# William / Jarvis\n\n{purpose}\n\nScaffolded from prompt {prompt_number}. Replace with the full README when ready.\n"
    return f"{purpose}\n\nScaffolded from prompt {prompt_number}. Replace with full content when ready.\n"


def tsx_stub(path_value: str, purpose: str, prompt_number: int) -> str:
    return (
        'export default function ScaffoldPage() {\n'
        '  return (\n'
        '    <main style={{ padding: 24 }}>\n'
        '      <h1>William / Jarvis</h1>\n'
        f'      <p>{purpose}</p>\n'
        f'      <small>Scaffolded from prompt {prompt_number} for {path_value}.</small>\n'
        '    </main>\n'
        '  );\n'
        '}\n'
    )


def json_stub(path_value: str, purpose: str, prompt_number: int) -> str:
    if path_value.endswith("package.json"):
        return json.dumps(
            {
                "name": "william-jarvis-dashboard",
                "version": "0.1.0",
                "private": True,
                "scripts": {
                    "dev": "next dev",
                    "build": "next build",
                    "start": "next start",
                    "lint": "next lint",
                },
                "dependencies": {
                    "next": "latest",
                    "react": "latest",
                    "react-dom": "latest",
                },
                "devDependencies": {
                    "typescript": "latest",
                    "@types/node": "latest",
                    "@types/react": "latest",
                    "@types/react-dom": "latest",
                },
            },
            indent=2,
        ) + "\n"
    return json.dumps(
        {
            "purpose": purpose,
            "prompt_number": prompt_number,
            "scaffold": True,
            "rules": {
                "safe_mode": True,
                "overwrite_existing_files": False,
            },
        },
        indent=2,
    ) + "\n"


def default_content(path_value: str, required_class_name: str, purpose: str, prompt_number: int, empty: bool) -> str:
    if empty:
        return ""
    suffix = Path(path_value).suffix.lower()
    if suffix == ".py":
        return python_stub(path_value, required_class_name, purpose, prompt_number)
    if suffix == ".tsx":
        return tsx_stub(path_value, purpose, prompt_number)
    if suffix == ".json":
        return json_stub(path_value, purpose, prompt_number)
    return text_stub(path_value, purpose, prompt_number)


def create_scaffold(root: Path, dry_run: bool = False, empty: bool = False) -> dict:
    root = root.resolve()
    created_files = []
    skipped_files = []
    created_dirs = set()

    for prompt_number, raw_path, required_class_name, purpose in FILE_SPECS:
        rel_path = normalize_path(raw_path)
        target = root / rel_path
        parent = target.parent

        if not parent.exists():
            created_dirs.add(str(parent.relative_to(root)))
            if not dry_run:
                parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            skipped_files.append(rel_path)
            continue

        created_files.append(rel_path)
        if not dry_run:
            content = default_content(rel_path, required_class_name, purpose, prompt_number, empty=empty)
            target.write_text(content, encoding="utf-8", newline="\n")

    return {
        "success": True,
        "root": str(root),
        "dry_run": dry_run,
        "empty_files": empty,
        "total_specs": len(FILE_SPECS),
        "created_files_count": len(created_files),
        "skipped_existing_count": len(skipped_files),
        "created_dirs_count": len(created_dirs),
        "created_files": created_files,
        "skipped_existing_files": skipped_files,
        "created_dirs": sorted(created_dirs),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create William / Jarvis folder and file scaffold without overwriting existing files."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Target project root folder. Default: current folder.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created, but do not create anything.",
    )
    parser.add_argument(
        "--empty",
        action="store_true",
        help="Create missing files as empty files instead of starter stubs.",
    )
    parser.add_argument(
        "--report",
        default="william_scaffold_report.json",
        help="Report JSON filename saved inside the root folder. Default: william_scaffold_report.json",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not args.dry_run:
        root.mkdir(parents=True, exist_ok=True)

    report = create_scaffold(root=root, dry_run=args.dry_run, empty=args.empty)

    print("William / Jarvis scaffold complete")
    print(f"Root: {report['root']}")
    print(f"Total file specs: {report['total_specs']}")
    print(f"Created files: {report['created_files_count']}")
    print(f"Skipped existing files: {report['skipped_existing_count']}")
    print(f"Created folders: {report['created_dirs_count']}")

    if args.dry_run:
        print("Dry run only. No files were changed.")
        print(json.dumps(report, indent=2))
        return 0

    report_path = Path(report["root"]) / args.report
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report saved: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
