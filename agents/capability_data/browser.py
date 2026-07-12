"""Capability data for the Browser Agent (agent_key="browser").

Purpose (from mission spec): Internet research, public page extraction, SEO,
competitor analysis, safe browser automation.

Live MVP behavior:
- Analyze public URLs and text.
- Use external_dependency_required for real browser automation if
  Playwright/browser worker not configured.
- Forms require approval.
"""

from __future__ import annotations

import re
from typing import List, Optional

from agents.capability_manifest import (
    AgentCapabilityEntry,
    CapabilityPermissionLevel as Perm,
    CapabilityRiskLevel as Risk,
    CapabilityStatus as Status,
)

AGENT_KEY = "browser"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _cap(
    index: int,
    name: str,
    description: str,
    risk: Risk,
    permission: Perm,
    status: Status,
    safe_mvp_behavior: str,
    verification_method: str,
    memory_policy: str,
    audit_required: bool = True,
    required_integrations: Optional[List[str]] = None,
) -> AgentCapabilityEntry:
    return AgentCapabilityEntry(
        id=f"{AGENT_KEY}.{index:03d}_{_slug(name)}",
        name=name,
        description=description,
        risk_level=risk,
        permission_level=permission,
        status=status,
        required_integrations=required_integrations or [],
        safe_mvp_behavior=safe_mvp_behavior,
        verification_method=verification_method,
        memory_policy=memory_policy,
        audit_required=audit_required,
    )


DB_SCOPED = "Stored in the DB-backed memory table, keyed by user_id + workspace_id; never mixed across tenants."
EPHEMERAL = "Held only for the lifetime of the active research session; not persisted to durable storage."
APPROVAL_GATED = "Persisted/executed only after explicit user/Security Agent approval; the request is logged either way."
NOT_PERSISTED = "Not persisted; returns an analysis result derived from already-fetched public content."

SCHEMA_CHECK = "VerificationAgent confirms response matches the normalized result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the memory table for the scoped user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."
BROWSER_CHECK = "VerificationAgent confirms the browser worker reported the navigation/action succeeded with the expected page state."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "Build Google/Bing search plans", "Construct a structured search-query plan for Google/Bing without executing it.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a structured query plan as text/data; no network request is made at this step.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(2, "Country/city/niche search filters", "Apply country/city/niche filters to a search plan.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Applies filter parameters to the structured search plan locally.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(3, "Open public URL adapter", "Navigate to a public URL in a browsing session.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns external_dependency_required until a Playwright/browser automation worker is configured.",
         BROWSER_CHECK, NOT_PERSISTED, audit_required=False, required_integrations=["playwright_browser_worker"]),
    _cap(4, "Manage multiple research tabs", "Open and track multiple browser tabs during a research session.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Requires a configured browser automation worker to maintain a real multi-tab session.",
         BROWSER_CHECK, EPHEMERAL, audit_required=False, required_integrations=["playwright_browser_worker"]),
    _cap(5, "Purpose-labeled tabs", "Label open research tabs with their research purpose.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Tags tab metadata once a real multi-tab browser session exists via a configured browser worker.",
         BROWSER_CHECK, EPHEMERAL, audit_required=False, required_integrations=["playwright_browser_worker"]),
    _cap(6, "Public page extraction", "Extract structured content from a public web page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses already-fetched HTML/text content using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(7, "Extract page title/meta", "Extract a page's title and meta tags.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses title/meta tags from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(8, "Extract H1/H2 headings", "Extract a page's H1/H2 heading structure.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses heading elements from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(9, "Extract CTA text", "Extract call-to-action button/link text from a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses CTA-like elements from already-fetched HTML using a local heuristic extractor.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(10, "Extract pricing tables", "Extract pricing plan/table data from a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses pricing-table structures from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(11, "Extract FAQs", "Extract frequently-asked-question content from a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses FAQ-like structures from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(12, "Extract testimonials", "Extract customer testimonial content from a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses testimonial-like structures from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(13, "Extract contact info", "Extract publicly listed contact information (email/phone/address) from a page.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Parses publicly listed contact details from already-fetched HTML; treats results as PII and redacts in shared summaries.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(14, "SEO title/meta/H1 analysis", "Analyze a page's SEO signal quality across title, meta, and H1 tags.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scores title/meta/H1 content against local SEO heuristics.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(15, "Schema/internal link analysis", "Analyze a page's structured-data schema and internal link structure.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses schema.org markup and internal links from already-fetched HTML.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(16, "Broken link detection", "Detect broken/dead links on a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Issues lightweight status checks against each discovered link and reports failures.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(17, "Landing page conversion audit", "Audit a landing page's likely conversion effectiveness.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scores extracted page content (CTAs, headings, trust signals) against local conversion heuristics.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(18, "Competitor comparison", "Compare extracted content/positioning across competitor pages.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates extraction results across multiple already-fetched competitor pages.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(19, "Review site research", "Research a product/company's presence on public review sites.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts and summarizes publicly available review content already fetched.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(20, "Market/niche research", "Research a target market or business niche using public sources.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates extraction/analysis results across multiple public sources.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(21, "SaaS feature research", "Research feature sets of comparable SaaS products.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts and compares feature lists/pricing across already-fetched competitor pages.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(22, "Lead magnet research", "Research lead-magnet offers used by comparable businesses.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts lead-magnet/opt-in offer content from already-fetched pages.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(23, "Ad copy inspiration research", "Research publicly visible ad copy for inspiration.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts publicly visible ad/promotional copy from already-fetched pages.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(24, "Screenshot capture for reports", "Capture a screenshot of a public page for inclusion in a report.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns external_dependency_required until a Playwright/browser automation worker capable of rendering and capturing is configured.",
         BROWSER_CHECK, NOT_PERSISTED, audit_required=False, required_integrations=["playwright_browser_worker"]),
    _cap(25, "Download public reports", "Download a publicly available report/document file.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Downloads the public file to local scoped storage via a standard HTTP request.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(26, "Public data extraction to CSV", "Export extracted public data to a CSV file.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the extracted data to a CSV file in scoped local storage.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(27, "Public data extraction to JSON", "Export extracted public data to a JSON file.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the extracted data to a JSON file in scoped local storage.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(28, "Source credibility ranking", "Rank research sources by an estimated credibility score.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scores sources against a local heuristic (domain age signals, HTTPS, citation presence).",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(29, "Multi-source comparison", "Compare findings across multiple research sources.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates and diffs extraction results across already-fetched sources.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(30, "Browser session memory", "Persist research session state (queries, tabs, findings) across turns.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores/reads session state via the DB-backed memory table.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(31, "Website change monitoring", "Monitor a public page for content changes over time.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Periodically re-fetches the page and diffs it against the last stored snapshot.", DB_CHECK, DB_SCOPED),
    _cap(32, "Pricing monitoring alerts", "Alert when a monitored competitor's public pricing changes.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Diffs extracted pricing-table data against the last stored snapshot and raises an alert on change.", DB_CHECK, DB_SCOPED),
    _cap(33, "Workflow learning from websites", "Derive a repeatable workflow definition from steps observed on a public site.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts a step sequence from already-fetched page content and forwards it to the Workflow Agent as a draft.",
         SCHEMA_CHECK, EPHEMERAL),
    _cap(34, "Form detection", "Detect form fields present on a page.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses form elements from already-fetched HTML using a local extraction pipeline.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(35, "Form fill with approval only", "Fill and submit a detected form on the user's behalf.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns approval_required and, once approved, requires a configured browser automation worker to fill and submit the form.",
         BROWSER_CHECK, APPROVAL_GATED, required_integrations=["playwright_browser_worker"]),
    _cap(36, "Never bypass CAPTCHA", "Refuse any request to bypass or solve a CAPTCHA challenge.",
         Risk.HIGH, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Detects CAPTCHA challenges and always refuses to bypass or automate past them.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(37, "Never bypass paywalls", "Refuse any request to bypass a site's paywall.",
         Risk.HIGH, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Detects paywalled content and always refuses to bypass or circumvent access restrictions.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(38, "Login-required site detection", "Detect when a target page requires authentication to view.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Detects login-wall indicators in already-fetched HTML and reports the page as inaccessible without credentials.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(39, "Browser safe-mode permissions", "Enforce a safe-mode permission set that limits browser automation scope.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Applies the workspace's safe-mode permission policy to every browser action request.", AUDIT_CHECK, DB_SCOPED, audit_required=False),
    _cap(40, "Cookie/session privacy policy", "Enforce a policy limiting cookie/session data retention during research.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Discards cookies/session state at the end of each research session rather than persisting them.", AUDIT_CHECK, EPHEMERAL, audit_required=False),
    _cap(41, "URL safety check with Security Agent", "Check a target URL's safety/reputation via the Security Agent before visiting it.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Checks the URL against a local reputation/blocklist heuristic and routes ambiguous cases to the Security Agent.",
         AUDIT_CHECK, NOT_PERSISTED),
    _cap(42, "Phishing page detection handoff", "Hand off a suspected phishing page to the Security Agent for review.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flags pages matching phishing heuristics and forwards them to the Security Agent.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(43, "Competitor content gap report", "Report content topics competitors cover that the user's site does not.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Diffs extracted topic/heading coverage between the user's site and competitor sites.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(44, "Local SEO audit", "Audit a page's local-SEO signals (NAP consistency, local schema, map listings).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scores extracted contact/schema data against local-SEO heuristics.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(45, "Page speed signal placeholder", "Report page-speed performance signals for a target page.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns external_dependency_required until a page-speed measurement API is configured; no fabricated score is returned.",
         UNAVAILABLE_CHECK, NOT_PERSISTED, audit_required=False, required_integrations=["pagespeed_insights_api_key"]),
    _cap(46, "Accessibility quick scan", "Run a quick static accessibility scan of a page (alt text, aria labels, contrast hints).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs local heuristic checks (missing alt text, aria attributes) against already-fetched HTML.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(47, "Screenshot proof handoff", "Hand off a captured screenshot to the Verification Agent as proof of a research finding.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Depends on screenshot capture; returns external_dependency_required until a browser automation worker is configured.",
         BROWSER_CHECK, EPHEMERAL, required_integrations=["playwright_browser_worker"]),
    _cap(48, "Research summary memory save", "Save a research session's summary findings to memory.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores the summary via the DB-backed memory table.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(49, "Browser Agent health/dependency check", "Report Browser Agent health and which browser automation adapters are configured.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports process health plus whether the Playwright/browser automation worker is configured.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(50, "Browser action audit log", "Log every browser research/automation action for audit purposes.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Writes an audit log row for each browser action performed.", AUDIT_CHECK, DB_SCOPED),
]

assert len(CAPABILITIES) == 50, f"browser capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
