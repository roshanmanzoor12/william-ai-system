"""
agents/super_agents/business_agent/config.py

Business Agent configuration module for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    - Business Agent settings
    - CRM provider configuration definitions
    - Report period presets
    - Role-based business permissions
    - SaaS user/workspace isolation validation
    - Security Agent compatibility hooks
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API/Registry-safe structured responses

Design Notes:
    This file is intentionally import-safe and uses only Python standard library modules.
    It does not execute external CRM calls, financial actions, browser actions, message actions,
    destructive actions, or system actions. It only defines and validates configuration.

    Every public method returns a structured dict in the William/Jarvis style:
        {
            "success": bool,
            "message": str,
            "data": dict/list/None,
            "error": str/None,
            "metadata": dict
        }

    This module can be imported before the rest of the Business Agent module exists.
"""

from __future__ import annotations

import copy
import logging
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


LOGGER = logging.getLogger(__name__)


CONFIG_VERSION = "1.0.0"
MODULE_NAME = "business_agent.config"
AGENT_NAME = "Business Agent"
REQUIRED_CLASS_NAME = "BusinessConfig"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class BusinessRole(str, Enum):
    """Business Agent role names used for permission checks."""

    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    SALES = "sales"
    SUPPORT = "support"
    ANALYST = "analyst"
    VIEWER = "viewer"
    BILLING = "billing"
    AUTOMATION = "automation"
    INTEGRATION = "integration"


class CRMProvider(str, Enum):
    """Supported CRM providers for configuration metadata."""

    INTERNAL = "internal"
    HUBSPOT = "hubspot"
    SALESFORCE = "salesforce"
    PIPEDRIVE = "pipedrive"
    ZOHO = "zoho"
    GHL = "gohighlevel"
    CUSTOM = "custom"


class ReportPeriod(str, Enum):
    """Supported report period keys."""

    TODAY = "today"
    YESTERDAY = "yesterday"
    LAST_7_DAYS = "last_7_days"
    LAST_14_DAYS = "last_14_days"
    LAST_30_DAYS = "last_30_days"
    LAST_60_DAYS = "last_60_days"
    LAST_90_DAYS = "last_90_days"
    WEEK_TO_DATE = "week_to_date"
    MONTH_TO_DATE = "month_to_date"
    QUARTER_TO_DATE = "quarter_to_date"
    YEAR_TO_DATE = "year_to_date"
    PREVIOUS_WEEK = "previous_week"
    PREVIOUS_MONTH = "previous_month"
    PREVIOUS_QUARTER = "previous_quarter"
    PREVIOUS_YEAR = "previous_year"
    CUSTOM = "custom"


class BusinessPermission(str, Enum):
    """Fine-grained Business Agent permission names."""

    READ_CONFIG = "business.config.read"
    UPDATE_CONFIG = "business.config.update"

    READ_CRM = "business.crm.read"
    WRITE_CRM = "business.crm.write"
    DELETE_CRM = "business.crm.delete"
    EXPORT_CRM = "business.crm.export"
    MANAGE_CRM_PROVIDERS = "business.crm.providers.manage"

    READ_LEADS = "business.leads.read"
    WRITE_LEADS = "business.leads.write"
    DELETE_LEADS = "business.leads.delete"
    ASSIGN_LEADS = "business.leads.assign"
    EXPORT_LEADS = "business.leads.export"

    READ_CLIENTS = "business.clients.read"
    WRITE_CLIENTS = "business.clients.write"
    DELETE_CLIENTS = "business.clients.delete"
    EXPORT_CLIENTS = "business.clients.export"

    READ_PIPELINE = "business.pipeline.read"
    WRITE_PIPELINE = "business.pipeline.write"
    DELETE_PIPELINE = "business.pipeline.delete"
    MANAGE_PIPELINE = "business.pipeline.manage"

    READ_CAMPAIGNS = "business.campaigns.read"
    WRITE_CAMPAIGNS = "business.campaigns.write"
    DELETE_CAMPAIGNS = "business.campaigns.delete"
    EXPORT_CAMPAIGNS = "business.campaigns.export"

    READ_REVENUE = "business.revenue.read"
    WRITE_REVENUE = "business.revenue.write"
    DELETE_REVENUE = "business.revenue.delete"
    EXPORT_REVENUE = "business.revenue.export"

    READ_ANALYTICS = "business.analytics.read"
    EXPORT_ANALYTICS = "business.analytics.export"

    READ_REPORTS = "business.reports.read"
    BUILD_REPORTS = "business.reports.build"
    EXPORT_REPORTS = "business.reports.export"
    SEND_REPORTS = "business.reports.send"

    READ_TASKS = "business.tasks.read"
    WRITE_TASKS = "business.tasks.write"
    DELETE_TASKS = "business.tasks.delete"
    ASSIGN_TASKS = "business.tasks.assign"

    READ_MEMORY = "business.memory.read"
    WRITE_MEMORY = "business.memory.write"

    MANAGE_ROLE_RULES = "business.roles.manage"
    VIEW_AUDIT = "business.audit.view"
    MANAGE_AUTOMATION = "business.automation.manage"


class SecurityAction(str, Enum):
    """Security-sensitive Business Agent action labels."""

    CONFIG_UPDATE = "business_config_update"
    CRM_PROVIDER_UPDATE = "crm_provider_update"
    CRM_PROVIDER_DELETE = "crm_provider_delete"
    ROLE_RULE_UPDATE = "role_rule_update"
    EXPORT_DATA = "business_data_export"
    DELETE_DATA = "business_data_delete"
    SEND_REPORT = "send_business_report"
    BILLING_OR_REVENUE_CHANGE = "billing_or_revenue_change"
    AUTOMATION_CHANGE = "business_automation_change"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CRMProviderConfig:
    """
    CRM provider configuration definition.

    Secrets are never hardcoded here. The secret_env_keys field documents which
    environment variables or external secret-manager keys are expected.
    """

    provider: str
    display_name: str
    enabled: bool = False
    auth_type: str = "none"
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    required_scopes: Tuple[str, ...] = field(default_factory=tuple)
    secret_env_keys: Tuple[str, ...] = field(default_factory=tuple)
    rate_limit_per_minute: int = 60
    timeout_seconds: int = 30
    supports_webhooks: bool = False
    supports_contacts: bool = True
    supports_companies: bool = True
    supports_deals: bool = True
    supports_tasks: bool = True
    supports_notes: bool = True
    supports_custom_fields: bool = True
    requires_security_approval_for_write: bool = True
    requires_workspace_mapping: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReportPeriodConfig:
    """Report period preset used by dashboards, report builder, and analytics engine."""

    key: str
    label: str
    description: str
    days: Optional[int] = None
    dashboard_default: bool = False
    supports_comparison: bool = True
    requires_custom_dates: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoleRule:
    """Role rule definition for Business Agent capability authorization."""

    role: str
    label: str
    permissions: Tuple[str, ...]
    can_manage_lower_roles: bool = False
    can_access_all_workspace_records: bool = False
    can_export_sensitive_data: bool = False
    requires_security_approval_for_sensitive_actions: bool = True
    description: str = ""


@dataclass(frozen=True)
class BusinessAgentSettings:
    """Top-level Business Agent settings."""

    default_crm_provider: str = CRMProvider.INTERNAL.value
    default_report_period: str = ReportPeriod.LAST_30_DAYS.value
    default_currency: str = "USD"
    default_timezone: str = "UTC"
    enable_audit_logging: bool = True
    enable_agent_events: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    enable_dashboard_metadata: bool = True
    require_security_for_exports: bool = True
    require_security_for_deletes: bool = True
    require_security_for_provider_changes: bool = True
    require_security_for_role_changes: bool = True
    require_workspace_id: bool = True
    require_user_id: bool = True
    max_report_rows: int = 10000
    max_export_rows: int = 50000
    max_bulk_update_records: int = 1000
    crm_request_timeout_seconds: int = 30
    crm_retry_attempts: int = 2
    memory_payload_max_chars: int = 4000
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


DEFAULT_CRM_PROVIDER_CONFIGS: Dict[str, CRMProviderConfig] = {
    CRMProvider.INTERNAL.value: CRMProviderConfig(
        provider=CRMProvider.INTERNAL.value,
        display_name="Internal CRM",
        enabled=True,
        auth_type="internal",
        base_url=None,
        api_version="v1",
        required_scopes=(),
        secret_env_keys=(),
        rate_limit_per_minute=600,
        timeout_seconds=10,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=False,
        requires_workspace_mapping=True,
        metadata={
            "storage_scope": "workspace",
            "description": "Native workspace-isolated CRM data store.",
        },
    ),
    CRMProvider.HUBSPOT.value: CRMProviderConfig(
        provider=CRMProvider.HUBSPOT.value,
        display_name="HubSpot",
        enabled=False,
        auth_type="oauth2_or_private_app_token",
        base_url="https://api.hubapi.com",
        api_version="v3",
        required_scopes=(
            "crm.objects.contacts.read",
            "crm.objects.contacts.write",
            "crm.objects.companies.read",
            "crm.objects.companies.write",
            "crm.objects.deals.read",
            "crm.objects.deals.write",
        ),
        secret_env_keys=("HUBSPOT_ACCESS_TOKEN", "HUBSPOT_CLIENT_ID", "HUBSPOT_CLIENT_SECRET"),
        rate_limit_per_minute=100,
        timeout_seconds=30,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={
            "provider_docs": "Use OAuth/private app tokens from a secure secret manager.",
            "external_ids_required": True,
        },
    ),
    CRMProvider.SALESFORCE.value: CRMProviderConfig(
        provider=CRMProvider.SALESFORCE.value,
        display_name="Salesforce",
        enabled=False,
        auth_type="oauth2",
        base_url=None,
        api_version="v60.0",
        required_scopes=("api", "refresh_token", "offline_access"),
        secret_env_keys=("SALESFORCE_CLIENT_ID", "SALESFORCE_CLIENT_SECRET", "SALESFORCE_REFRESH_TOKEN"),
        rate_limit_per_minute=120,
        timeout_seconds=30,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={
            "base_url_note": "Salesforce instance URL must be stored per workspace/provider connection.",
            "external_ids_required": True,
        },
    ),
    CRMProvider.PIPEDRIVE.value: CRMProviderConfig(
        provider=CRMProvider.PIPEDRIVE.value,
        display_name="Pipedrive",
        enabled=False,
        auth_type="api_token_or_oauth2",
        base_url="https://api.pipedrive.com",
        api_version="v1",
        required_scopes=("contacts:read", "contacts:write", "deals:read", "deals:write"),
        secret_env_keys=("PIPEDRIVE_API_TOKEN", "PIPEDRIVE_CLIENT_ID", "PIPEDRIVE_CLIENT_SECRET"),
        rate_limit_per_minute=80,
        timeout_seconds=30,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={"external_ids_required": True},
    ),
    CRMProvider.ZOHO.value: CRMProviderConfig(
        provider=CRMProvider.ZOHO.value,
        display_name="Zoho CRM",
        enabled=False,
        auth_type="oauth2",
        base_url="https://www.zohoapis.com/crm",
        api_version="v5",
        required_scopes=(
            "ZohoCRM.modules.ALL",
            "ZohoCRM.settings.fields.READ",
        ),
        secret_env_keys=("ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "ZOHO_REFRESH_TOKEN"),
        rate_limit_per_minute=100,
        timeout_seconds=30,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={"external_ids_required": True},
    ),
    CRMProvider.GHL.value: CRMProviderConfig(
        provider=CRMProvider.GHL.value,
        display_name="GoHighLevel",
        enabled=False,
        auth_type="oauth2_or_location_token",
        base_url="https://services.leadconnectorhq.com",
        api_version="2021-07-28",
        required_scopes=("contacts.readonly", "contacts.write", "opportunities.readonly", "opportunities.write"),
        secret_env_keys=("GHL_ACCESS_TOKEN", "GHL_LOCATION_ID", "GHL_CLIENT_ID", "GHL_CLIENT_SECRET"),
        rate_limit_per_minute=60,
        timeout_seconds=30,
        supports_webhooks=True,
        supports_contacts=True,
        supports_companies=False,
        supports_deals=True,
        supports_tasks=True,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={
            "location_id_required": True,
            "external_ids_required": True,
        },
    ),
    CRMProvider.CUSTOM.value: CRMProviderConfig(
        provider=CRMProvider.CUSTOM.value,
        display_name="Custom CRM",
        enabled=False,
        auth_type="custom",
        base_url=None,
        api_version=None,
        required_scopes=(),
        secret_env_keys=("CUSTOM_CRM_API_KEY", "CUSTOM_CRM_BASE_URL"),
        rate_limit_per_minute=60,
        timeout_seconds=30,
        supports_webhooks=False,
        supports_contacts=True,
        supports_companies=True,
        supports_deals=True,
        supports_tasks=False,
        supports_notes=True,
        supports_custom_fields=True,
        requires_security_approval_for_write=True,
        requires_workspace_mapping=True,
        metadata={
            "requires_adapter": True,
            "description": "For future plugin-style CRM adapters.",
        },
    ),
}


DEFAULT_REPORT_PERIODS: Dict[str, ReportPeriodConfig] = {
    ReportPeriod.TODAY.value: ReportPeriodConfig(
        key=ReportPeriod.TODAY.value,
        label="Today",
        description="Current calendar day.",
        days=1,
        dashboard_default=False,
    ),
    ReportPeriod.YESTERDAY.value: ReportPeriodConfig(
        key=ReportPeriod.YESTERDAY.value,
        label="Yesterday",
        description="Previous calendar day.",
        days=1,
        dashboard_default=False,
    ),
    ReportPeriod.LAST_7_DAYS.value: ReportPeriodConfig(
        key=ReportPeriod.LAST_7_DAYS.value,
        label="Last 7 Days",
        description="Rolling 7-day period.",
        days=7,
        dashboard_default=False,
    ),
    ReportPeriod.LAST_14_DAYS.value: ReportPeriodConfig(
        key=ReportPeriod.LAST_14_DAYS.value,
        label="Last 14 Days",
        description="Rolling 14-day period.",
        days=14,
        dashboard_default=False,
    ),
    ReportPeriod.LAST_30_DAYS.value: ReportPeriodConfig(
        key=ReportPeriod.LAST_30_DAYS.value,
        label="Last 30 Days",
        description="Rolling 30-day period.",
        days=30,
        dashboard_default=True,
    ),
    ReportPeriod.LAST_60_DAYS.value: ReportPeriodConfig(
        key=ReportPeriod.LAST_60_DAYS.value,
        label="Last 60 Days",
        description="Rolling 60-day period.",
        days=60,
        dashboard_default=False,
    ),
    ReportPeriod.LAST_90_DAYS.value: ReportPeriodConfig(
        key=ReportPeriod.LAST_90_DAYS.value,
        label="Last 90 Days",
        description="Rolling 90-day period.",
        days=90,
        dashboard_default=False,
    ),
    ReportPeriod.WEEK_TO_DATE.value: ReportPeriodConfig(
        key=ReportPeriod.WEEK_TO_DATE.value,
        label="Week to Date",
        description="Current week to date.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.MONTH_TO_DATE.value: ReportPeriodConfig(
        key=ReportPeriod.MONTH_TO_DATE.value,
        label="Month to Date",
        description="Current month to date.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.QUARTER_TO_DATE.value: ReportPeriodConfig(
        key=ReportPeriod.QUARTER_TO_DATE.value,
        label="Quarter to Date",
        description="Current quarter to date.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.YEAR_TO_DATE.value: ReportPeriodConfig(
        key=ReportPeriod.YEAR_TO_DATE.value,
        label="Year to Date",
        description="Current year to date.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.PREVIOUS_WEEK.value: ReportPeriodConfig(
        key=ReportPeriod.PREVIOUS_WEEK.value,
        label="Previous Week",
        description="Previous full calendar week.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.PREVIOUS_MONTH.value: ReportPeriodConfig(
        key=ReportPeriod.PREVIOUS_MONTH.value,
        label="Previous Month",
        description="Previous full calendar month.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.PREVIOUS_QUARTER.value: ReportPeriodConfig(
        key=ReportPeriod.PREVIOUS_QUARTER.value,
        label="Previous Quarter",
        description="Previous full calendar quarter.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.PREVIOUS_YEAR.value: ReportPeriodConfig(
        key=ReportPeriod.PREVIOUS_YEAR.value,
        label="Previous Year",
        description="Previous full calendar year.",
        days=None,
        dashboard_default=False,
    ),
    ReportPeriod.CUSTOM.value: ReportPeriodConfig(
        key=ReportPeriod.CUSTOM.value,
        label="Custom Range",
        description="Custom start and end dates supplied by the caller.",
        days=None,
        dashboard_default=False,
        requires_custom_dates=True,
    ),
}


_OWNER_PERMISSIONS = tuple(permission.value for permission in BusinessPermission)

_ADMIN_PERMISSIONS = tuple(
    permission.value
    for permission in BusinessPermission
    if permission
    not in {
        BusinessPermission.DELETE_CRM,
        BusinessPermission.DELETE_CLIENTS,
        BusinessPermission.DELETE_REVENUE,
    }
)

_MANAGER_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.WRITE_CRM.value,
    BusinessPermission.EXPORT_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.WRITE_LEADS.value,
    BusinessPermission.ASSIGN_LEADS.value,
    BusinessPermission.EXPORT_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.WRITE_CLIENTS.value,
    BusinessPermission.EXPORT_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.WRITE_PIPELINE.value,
    BusinessPermission.MANAGE_PIPELINE.value,
    BusinessPermission.READ_CAMPAIGNS.value,
    BusinessPermission.WRITE_CAMPAIGNS.value,
    BusinessPermission.EXPORT_CAMPAIGNS.value,
    BusinessPermission.READ_REVENUE.value,
    BusinessPermission.EXPORT_REVENUE.value,
    BusinessPermission.READ_ANALYTICS.value,
    BusinessPermission.EXPORT_ANALYTICS.value,
    BusinessPermission.READ_REPORTS.value,
    BusinessPermission.BUILD_REPORTS.value,
    BusinessPermission.EXPORT_REPORTS.value,
    BusinessPermission.READ_TASKS.value,
    BusinessPermission.WRITE_TASKS.value,
    BusinessPermission.ASSIGN_TASKS.value,
    BusinessPermission.READ_MEMORY.value,
)

_SALES_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.WRITE_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.WRITE_LEADS.value,
    BusinessPermission.ASSIGN_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.WRITE_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.WRITE_PIPELINE.value,
    BusinessPermission.READ_REPORTS.value,
    BusinessPermission.READ_TASKS.value,
    BusinessPermission.WRITE_TASKS.value,
    BusinessPermission.READ_MEMORY.value,
    BusinessPermission.WRITE_MEMORY.value,
)

_SUPPORT_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.WRITE_CLIENTS.value,
    BusinessPermission.READ_TASKS.value,
    BusinessPermission.WRITE_TASKS.value,
    BusinessPermission.READ_MEMORY.value,
    BusinessPermission.WRITE_MEMORY.value,
)

_ANALYST_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.READ_CAMPAIGNS.value,
    BusinessPermission.READ_REVENUE.value,
    BusinessPermission.READ_ANALYTICS.value,
    BusinessPermission.EXPORT_ANALYTICS.value,
    BusinessPermission.READ_REPORTS.value,
    BusinessPermission.BUILD_REPORTS.value,
    BusinessPermission.EXPORT_REPORTS.value,
    BusinessPermission.READ_TASKS.value,
)

_VIEWER_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.READ_CAMPAIGNS.value,
    BusinessPermission.READ_ANALYTICS.value,
    BusinessPermission.READ_REPORTS.value,
    BusinessPermission.READ_TASKS.value,
)

_BILLING_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.READ_REVENUE.value,
    BusinessPermission.WRITE_REVENUE.value,
    BusinessPermission.EXPORT_REVENUE.value,
    BusinessPermission.READ_ANALYTICS.value,
    BusinessPermission.READ_REPORTS.value,
    BusinessPermission.BUILD_REPORTS.value,
    BusinessPermission.EXPORT_REPORTS.value,
    BusinessPermission.READ_TASKS.value,
)

_AUTOMATION_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.WRITE_CRM.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.WRITE_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.WRITE_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.WRITE_PIPELINE.value,
    BusinessPermission.READ_TASKS.value,
    BusinessPermission.WRITE_TASKS.value,
    BusinessPermission.READ_MEMORY.value,
    BusinessPermission.WRITE_MEMORY.value,
    BusinessPermission.MANAGE_AUTOMATION.value,
)

_INTEGRATION_PERMISSIONS = (
    BusinessPermission.READ_CONFIG.value,
    BusinessPermission.UPDATE_CONFIG.value,
    BusinessPermission.READ_CRM.value,
    BusinessPermission.WRITE_CRM.value,
    BusinessPermission.MANAGE_CRM_PROVIDERS.value,
    BusinessPermission.READ_LEADS.value,
    BusinessPermission.WRITE_LEADS.value,
    BusinessPermission.READ_CLIENTS.value,
    BusinessPermission.WRITE_CLIENTS.value,
    BusinessPermission.READ_PIPELINE.value,
    BusinessPermission.WRITE_PIPELINE.value,
    BusinessPermission.MANAGE_AUTOMATION.value,
)


DEFAULT_ROLE_RULES: Dict[str, RoleRule] = {
    BusinessRole.OWNER.value: RoleRule(
        role=BusinessRole.OWNER.value,
        label="Owner",
        permissions=_OWNER_PERMISSIONS,
        can_manage_lower_roles=True,
        can_access_all_workspace_records=True,
        can_export_sensitive_data=True,
        requires_security_approval_for_sensitive_actions=True,
        description="Full Business Agent access. Sensitive actions still route through Security Agent.",
    ),
    BusinessRole.ADMIN.value: RoleRule(
        role=BusinessRole.ADMIN.value,
        label="Admin",
        permissions=_ADMIN_PERMISSIONS,
        can_manage_lower_roles=True,
        can_access_all_workspace_records=True,
        can_export_sensitive_data=True,
        requires_security_approval_for_sensitive_actions=True,
        description="High-level workspace administration without unrestricted destructive access.",
    ),
    BusinessRole.MANAGER.value: RoleRule(
        role=BusinessRole.MANAGER.value,
        label="Manager",
        permissions=_MANAGER_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=True,
        can_export_sensitive_data=True,
        requires_security_approval_for_sensitive_actions=True,
        description="Manages business workflows, reports, pipeline, leads, clients, and tasks.",
    ),
    BusinessRole.SALES.value: RoleRule(
        role=BusinessRole.SALES.value,
        label="Sales",
        permissions=_SALES_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Sales-focused access to leads, CRM records, pipeline, tasks, and notes.",
    ),
    BusinessRole.SUPPORT.value: RoleRule(
        role=BusinessRole.SUPPORT.value,
        label="Support",
        permissions=_SUPPORT_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Client support access for client notes, tasks, and safe CRM reading.",
    ),
    BusinessRole.ANALYST.value: RoleRule(
        role=BusinessRole.ANALYST.value,
        label="Analyst",
        permissions=_ANALYST_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=True,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Analytics/reporting role with limited write access.",
    ),
    BusinessRole.VIEWER.value: RoleRule(
        role=BusinessRole.VIEWER.value,
        label="Viewer",
        permissions=_VIEWER_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Read-only role for non-sensitive business visibility.",
    ),
    BusinessRole.BILLING.value: RoleRule(
        role=BusinessRole.BILLING.value,
        label="Billing",
        permissions=_BILLING_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=True,
        requires_security_approval_for_sensitive_actions=True,
        description="Revenue, invoices, and billing report access.",
    ),
    BusinessRole.AUTOMATION.value: RoleRule(
        role=BusinessRole.AUTOMATION.value,
        label="Automation",
        permissions=_AUTOMATION_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Service role for workflow automations under workspace isolation.",
    ),
    BusinessRole.INTEGRATION.value: RoleRule(
        role=BusinessRole.INTEGRATION.value,
        label="Integration",
        permissions=_INTEGRATION_PERMISSIONS,
        can_manage_lower_roles=False,
        can_access_all_workspace_records=False,
        can_export_sensitive_data=False,
        requires_security_approval_for_sensitive_actions=True,
        description="Service role for CRM/provider integration configuration.",
    ),
}


SENSITIVE_ACTIONS: Dict[str, str] = {
    "update_config": SecurityAction.CONFIG_UPDATE.value,
    "set_setting": SecurityAction.CONFIG_UPDATE.value,
    "enable_crm_provider": SecurityAction.CRM_PROVIDER_UPDATE.value,
    "disable_crm_provider": SecurityAction.CRM_PROVIDER_UPDATE.value,
    "upsert_crm_provider": SecurityAction.CRM_PROVIDER_UPDATE.value,
    "delete_crm_provider": SecurityAction.CRM_PROVIDER_DELETE.value,
    "update_role_rule": SecurityAction.ROLE_RULE_UPDATE.value,
    "delete_role_rule": SecurityAction.ROLE_RULE_UPDATE.value,
    "export_config": SecurityAction.EXPORT_DATA.value,
    "send_report": SecurityAction.SEND_REPORT.value,
    "update_revenue": SecurityAction.BILLING_OR_REVENUE_CHANGE.value,
    "manage_automation": SecurityAction.AUTOMATION_CHANGE.value,
}


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """Return current UTC datetime in ISO format."""

    return datetime.now(timezone.utc).isoformat()


def _safe_deepcopy(value: Any) -> Any:
    """Safely deep-copy config values for external response payloads."""

    return copy.deepcopy(value)


def _normalize_key(value: Any) -> str:
    """Normalize arbitrary text into a config-safe key."""

    if value is None:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9_.:-]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def _is_non_empty_string(value: Any) -> bool:
    """Return True when value is a non-empty string."""

    return isinstance(value, str) and bool(value.strip())


def _dataclass_to_dict(value: Any) -> Dict[str, Any]:
    """Convert dataclass config values to plain dicts."""

    data = asdict(value)
    for key, item in list(data.items()):
        if isinstance(item, tuple):
            data[key] = list(item)
    return data


def _env_flag(name: str, default: bool) -> bool:
    """Read a boolean environment flag safely."""

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    """Read an integer environment value safely with optional bounds."""

    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default

    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)

    return value


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------


class BusinessConfig:
    """
    Business Agent configuration manager.

    This class provides safe, structured access to Business Agent settings,
    CRM provider configs, report periods, and role rules.

    Integration points:
        - Master Agent:
            Can route config-related tasks to public methods on this class.
        - Security Agent:
            Sensitive config, provider, export, and role changes can be checked
            through `_requires_security_check()` and `_request_security_approval()`.
        - Verification Agent:
            Public methods include verification payloads in metadata where useful.
        - Memory Agent:
            Public methods can prepare memory-compatible payloads without storing
            secrets or cross-workspace data.
        - Dashboard/API:
            Public methods return JSON-safe dicts.
        - Agent Registry/Loader:
            `registry_manifest()` exposes import-safe module metadata.
    """

    module_name = MODULE_NAME
    agent_name = AGENT_NAME
    config_version = CONFIG_VERSION

    def __init__(
        self,
        *,
        settings: Optional[BusinessAgentSettings] = None,
        crm_providers: Optional[Mapping[str, CRMProviderConfig | Mapping[str, Any]]] = None,
        report_periods: Optional[Mapping[str, ReportPeriodConfig | Mapping[str, Any]]] = None,
        role_rules: Optional[Mapping[str, RoleRule | Mapping[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.logger = logger or LOGGER
        self.settings = settings or self._settings_from_environment()
        self._crm_providers: Dict[str, CRMProviderConfig] = self._build_crm_provider_configs(crm_providers)
        self._report_periods: Dict[str, ReportPeriodConfig] = self._build_report_period_configs(report_periods)
        self._role_rules: Dict[str, RoleRule] = self._build_role_rules(role_rules)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _settings_from_environment(self) -> BusinessAgentSettings:
        """Build settings from safe defaults plus optional environment overrides."""

        return BusinessAgentSettings(
            default_crm_provider=_normalize_key(
                os.getenv("WILLIAM_BUSINESS_DEFAULT_CRM_PROVIDER", CRMProvider.INTERNAL.value)
            )
            or CRMProvider.INTERNAL.value,
            default_report_period=_normalize_key(
                os.getenv("WILLIAM_BUSINESS_DEFAULT_REPORT_PERIOD", ReportPeriod.LAST_30_DAYS.value)
            )
            or ReportPeriod.LAST_30_DAYS.value,
            default_currency=(os.getenv("WILLIAM_BUSINESS_DEFAULT_CURRENCY", "USD") or "USD").strip().upper(),
            default_timezone=(os.getenv("WILLIAM_BUSINESS_DEFAULT_TIMEZONE", "UTC") or "UTC").strip(),
            enable_audit_logging=_env_flag("WILLIAM_BUSINESS_ENABLE_AUDIT_LOGGING", True),
            enable_agent_events=_env_flag("WILLIAM_BUSINESS_ENABLE_AGENT_EVENTS", True),
            enable_memory_payloads=_env_flag("WILLIAM_BUSINESS_ENABLE_MEMORY_PAYLOADS", True),
            enable_verification_payloads=_env_flag("WILLIAM_BUSINESS_ENABLE_VERIFICATION_PAYLOADS", True),
            enable_dashboard_metadata=_env_flag("WILLIAM_BUSINESS_ENABLE_DASHBOARD_METADATA", True),
            require_security_for_exports=_env_flag("WILLIAM_BUSINESS_REQUIRE_SECURITY_FOR_EXPORTS", True),
            require_security_for_deletes=_env_flag("WILLIAM_BUSINESS_REQUIRE_SECURITY_FOR_DELETES", True),
            require_security_for_provider_changes=_env_flag("WILLIAM_BUSINESS_REQUIRE_SECURITY_FOR_PROVIDER_CHANGES", True),
            require_security_for_role_changes=_env_flag("WILLIAM_BUSINESS_REQUIRE_SECURITY_FOR_ROLE_CHANGES", True),
            require_workspace_id=_env_flag("WILLIAM_BUSINESS_REQUIRE_WORKSPACE_ID", True),
            require_user_id=_env_flag("WILLIAM_BUSINESS_REQUIRE_USER_ID", True),
            max_report_rows=_env_int("WILLIAM_BUSINESS_MAX_REPORT_ROWS", 10000, minimum=1, maximum=500000),
            max_export_rows=_env_int("WILLIAM_BUSINESS_MAX_EXPORT_ROWS", 50000, minimum=1, maximum=1000000),
            max_bulk_update_records=_env_int("WILLIAM_BUSINESS_MAX_BULK_UPDATE_RECORDS", 1000, minimum=1, maximum=100000),
            crm_request_timeout_seconds=_env_int("WILLIAM_BUSINESS_CRM_TIMEOUT_SECONDS", 30, minimum=1, maximum=300),
            crm_retry_attempts=_env_int("WILLIAM_BUSINESS_CRM_RETRY_ATTEMPTS", 2, minimum=0, maximum=10),
            memory_payload_max_chars=_env_int("WILLIAM_BUSINESS_MEMORY_PAYLOAD_MAX_CHARS", 4000, minimum=256, maximum=50000),
            metadata={
                "source": "environment_with_safe_defaults",
                "secrets_hardcoded": False,
            },
        )

    def _build_crm_provider_configs(
        self,
        overrides: Optional[Mapping[str, CRMProviderConfig | Mapping[str, Any]]],
    ) -> Dict[str, CRMProviderConfig]:
        """Build CRM provider configs from defaults plus optional overrides."""

        configs = dict(DEFAULT_CRM_PROVIDER_CONFIGS)

        if not overrides:
            return configs

        for raw_key, raw_value in overrides.items():
            key = _normalize_key(raw_key)
            if not key:
                continue

            if isinstance(raw_value, CRMProviderConfig):
                configs[key] = raw_value
                continue

            if isinstance(raw_value, Mapping):
                base_data: Dict[str, Any] = {}
                if key in configs:
                    base_data = _dataclass_to_dict(configs[key])
                base_data.update(dict(raw_value))
                base_data["provider"] = _normalize_key(base_data.get("provider") or key) or key
                base_data["display_name"] = str(base_data.get("display_name") or base_data["provider"]).strip()
                base_data["required_scopes"] = tuple(base_data.get("required_scopes") or ())
                base_data["secret_env_keys"] = tuple(base_data.get("secret_env_keys") or ())
                configs[key] = CRMProviderConfig(**base_data)

        return configs

    def _build_report_period_configs(
        self,
        overrides: Optional[Mapping[str, ReportPeriodConfig | Mapping[str, Any]]],
    ) -> Dict[str, ReportPeriodConfig]:
        """Build report period configs from defaults plus optional overrides."""

        periods = dict(DEFAULT_REPORT_PERIODS)

        if not overrides:
            return periods

        for raw_key, raw_value in overrides.items():
            key = _normalize_key(raw_key)
            if not key:
                continue

            if isinstance(raw_value, ReportPeriodConfig):
                periods[key] = raw_value
                continue

            if isinstance(raw_value, Mapping):
                base_data: Dict[str, Any] = {}
                if key in periods:
                    base_data = _dataclass_to_dict(periods[key])
                base_data.update(dict(raw_value))
                base_data["key"] = _normalize_key(base_data.get("key") or key) or key
                base_data["label"] = str(base_data.get("label") or base_data["key"]).strip()
                base_data["description"] = str(base_data.get("description") or "").strip()
                periods[key] = ReportPeriodConfig(**base_data)

        return periods

    def _build_role_rules(
        self,
        overrides: Optional[Mapping[str, RoleRule | Mapping[str, Any]]],
    ) -> Dict[str, RoleRule]:
        """Build role rules from defaults plus optional overrides."""

        roles = dict(DEFAULT_ROLE_RULES)

        if not overrides:
            return roles

        for raw_key, raw_value in overrides.items():
            key = _normalize_key(raw_key)
            if not key:
                continue

            if isinstance(raw_value, RoleRule):
                roles[key] = raw_value
                continue

            if isinstance(raw_value, Mapping):
                base_data: Dict[str, Any] = {}
                if key in roles:
                    base_data = _dataclass_to_dict(roles[key])
                base_data.update(dict(raw_value))
                base_data["role"] = _normalize_key(base_data.get("role") or key) or key
                base_data["label"] = str(base_data.get("label") or base_data["role"]).strip()
                base_data["permissions"] = tuple(str(item) for item in (base_data.get("permissions") or ()))
                roles[key] = RoleRule(**base_data)

        return roles

    # ------------------------------------------------------------------
    # Required Compatibility Hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Ensures all user/workspace-scoped operations remain isolated.
        """

        if context is None:
            return self._error_result(
                "Task context is required.",
                error="missing_task_context",
                metadata={"hook": "_validate_task_context"},
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if self.settings.require_user_id and not _is_non_empty_string(user_id):
            return self._error_result(
                "user_id is required for Business Agent configuration access.",
                error="missing_user_id",
                metadata={"hook": "_validate_task_context"},
            )

        if self.settings.require_workspace_id and not _is_non_empty_string(workspace_id):
            return self._error_result(
                "workspace_id is required for Business Agent configuration access.",
                error="missing_workspace_id",
                metadata={"hook": "_validate_task_context"},
            )

        role = _normalize_key(context.get("role") or BusinessRole.VIEWER.value) or BusinessRole.VIEWER.value

        validated = {
            "user_id": str(user_id).strip() if user_id is not None else None,
            "workspace_id": str(workspace_id).strip() if workspace_id is not None else None,
            "role": role,
            "request_id": str(context.get("request_id") or uuid.uuid4()),
            "source": str(context.get("source") or "business_config"),
            "validated_at": _utc_now_iso(),
        }

        return self._safe_result(
            "Task context validated.",
            data=validated,
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action requires Security Agent approval.

        This method only determines requirement. It does not approve or execute anything.
        """

        normalized_action = _normalize_key(action)

        if normalized_action in {"delete", "delete_data", "delete_crm_provider", "delete_role_rule"}:
            return True

        if normalized_action in {"export", "export_config"}:
            return bool(self.settings.require_security_for_exports)

        if normalized_action in {"update_config", "set_setting"}:
            return True

        if normalized_action in {"enable_crm_provider", "disable_crm_provider", "upsert_crm_provider"}:
            return bool(self.settings.require_security_for_provider_changes)

        if normalized_action in {"update_role_rule", "delete_role_rule"}:
            return bool(self.settings.require_security_for_role_changes)

        if payload:
            if payload.get("contains_sensitive_data") is True:
                return True
            if payload.get("destructive") is True:
                return True
            if payload.get("external_provider_write") is True:
                return True

        role = _normalize_key(context.get("role")) if context else ""
        role_rule = self._role_rules.get(role)
        if role_rule and role_rule.requires_security_approval_for_sensitive_actions:
            if normalized_action in SENSITIVE_ACTIONS:
                return True

        return normalized_action in SENSITIVE_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request payload.

        Import-safe fallback behavior:
            This file does not call a real Security Agent directly. It returns a structured
            approval request that the Master Agent or Router can forward to Security Agent.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        validated_context = validation["data"]
        security_action = SENSITIVE_ACTIONS.get(_normalize_key(action), _normalize_key(action))

        approval_payload = {
            "approval_required": self._requires_security_check(action, validated_context, payload),
            "security_action": security_action,
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "action": _normalize_key(action),
            "user_id": validated_context.get("user_id"),
            "workspace_id": validated_context.get("workspace_id"),
            "request_id": validated_context.get("request_id"),
            "payload_summary": self._redact_sensitive_payload(payload or {}),
            "created_at": _utc_now_iso(),
        }

        return self._safe_result(
            "Security approval payload prepared.",
            data=approval_payload,
            metadata={"hook": "_request_security_approval", "route_to": "Security Agent"},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        result: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent payload.

        This payload allows the Verification Agent to confirm configuration changes,
        access checks, and output structure without exposing secrets.
        """

        validation = self._validate_task_context(context)
        validated_context = validation.get("data") if validation.get("success") else {}

        payload = {
            "verification_type": "business_config_operation",
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "config_version": CONFIG_VERSION,
            "action": _normalize_key(action),
            "user_id": validated_context.get("user_id"),
            "workspace_id": validated_context.get("workspace_id"),
            "request_id": validated_context.get("request_id"),
            "result_success": bool(result.get("success")) if isinstance(result, Mapping) else None,
            "result_message": result.get("message") if isinstance(result, Mapping) else None,
            "secrets_exposed": False,
            "created_at": _utc_now_iso(),
        }

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        summary: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent-compatible payload.

        This method never stores secrets. It only prepares a sanitized summary that
        can be stored if the Memory Agent policy allows it.
        """

        validation = self._validate_task_context(context)
        validated_context = validation.get("data") if validation.get("success") else {}

        safe_summary = str(summary or f"Business configuration action performed: {_normalize_key(action)}")
        max_chars = self.settings.memory_payload_max_chars
        if len(safe_summary) > max_chars:
            safe_summary = safe_summary[: max_chars - 3] + "..."

        return {
            "memory_type": "business_config",
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "action": _normalize_key(action),
            "user_id": validated_context.get("user_id"),
            "workspace_id": validated_context.get("workspace_id"),
            "summary": safe_summary,
            "data": self._redact_sensitive_payload(data or {}),
            "created_at": _utc_now_iso(),
            "safe_for_long_term_memory": True,
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit a structured agent event.

        Import-safe behavior:
            This method logs locally and returns the event object. Future event bus
            adapters can consume this structure.
        """

        if not self.settings.enable_agent_events:
            return self._safe_result(
                "Agent events are disabled.",
                data={"emitted": False},
                metadata={"hook": "_emit_agent_event"},
            )

        validation = self._validate_task_context(context)
        validated_context = validation.get("data") if validation.get("success") else {}

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": _normalize_key(event_name),
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "user_id": validated_context.get("user_id"),
            "workspace_id": validated_context.get("workspace_id"),
            "request_id": validated_context.get("request_id"),
            "payload": self._redact_sensitive_payload(payload or {}),
            "created_at": _utc_now_iso(),
        }

        self.logger.info("BusinessConfig event emitted: %s", event)

        return self._safe_result(
            "Agent event emitted.",
            data=event,
            metadata={"hook": "_emit_agent_event"},
        )

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Log a structured audit event.

        Import-safe behavior:
            This method writes to Python logging only. Future audit storage can use
            the returned event structure.
        """

        if not self.settings.enable_audit_logging:
            return self._safe_result(
                "Audit logging is disabled.",
                data={"logged": False},
                metadata={"hook": "_log_audit_event"},
            )

        validation = self._validate_task_context(context)
        validated_context = validation.get("data") if validation.get("success") else {}

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "action": _normalize_key(action),
            "user_id": validated_context.get("user_id"),
            "workspace_id": validated_context.get("workspace_id"),
            "request_id": validated_context.get("request_id"),
            "success": bool(success),
            "error": error,
            "payload": self._redact_sensitive_payload(payload or {}),
            "created_at": _utc_now_iso(),
        }

        if success:
            self.logger.info("BusinessConfig audit event: %s", audit_event)
        else:
            self.logger.warning("BusinessConfig audit event failed: %s", audit_event)

        return self._safe_result(
            "Audit event logged.",
            data=audit_event,
            metadata={"hook": "_log_audit_event"},
        )

    def _safe_result(
        self,
        message: str,
        data: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard successful William/Jarvis result dict."""

        return {
            "success": True,
            "message": message,
            "data": data,
            "error": None,
            "metadata": self._base_metadata(metadata),
        }

    def _error_result(
        self,
        message: str,
        error: str = "business_config_error",
        data: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard failed William/Jarvis result dict."""

        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error,
            "metadata": self._base_metadata(metadata),
        }

    # ------------------------------------------------------------------
    # Public Settings Methods
    # ------------------------------------------------------------------

    def get_settings(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return Business Agent settings."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to read Business Agent settings.",
                error="permission_denied",
                metadata={"method": "get_settings"},
            )

        data = _dataclass_to_dict(self.settings)
        result = self._safe_result(
            "Business Agent settings loaded.",
            data=data,
            metadata={
                "method": "get_settings",
                "verification": self._prepare_verification_payload("get_settings", context),
            },
        )
        self._log_audit_event("get_settings", context, {"settings_keys": list(data.keys())}, success=True)
        return result

    def get_setting(self, key: str, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return one Business Agent setting by key."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to read Business Agent settings.",
                error="permission_denied",
                metadata={"method": "get_setting"},
            )

        normalized_key = _normalize_key(key)
        settings_dict = _dataclass_to_dict(self.settings)

        if normalized_key not in settings_dict:
            return self._error_result(
                f"Unknown Business Agent setting: {key}",
                error="unknown_setting",
                metadata={"method": "get_setting", "requested_key": key},
            )

        return self._safe_result(
            "Business Agent setting loaded.",
            data={"key": normalized_key, "value": settings_dict[normalized_key]},
            metadata={"method": "get_setting"},
        )

    def update_setting(
        self,
        key: str,
        value: Any,
        context: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Update a mutable Business Agent setting in memory.

        Sensitive updates require Security Agent approval. This method does not
        persist to disk or database; future API/service layers can persist the result.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        permission = self.has_permission(context, BusinessPermission.UPDATE_CONFIG.value)
        if not permission.get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to update Business Agent settings.",
                error="permission_denied",
                metadata={"method": "update_setting"},
            )

        if self._requires_security_check("set_setting", context, {"setting_key": key}) and not security_approved:
            return self._error_result(
                "Security approval is required before updating this setting.",
                error="security_approval_required",
                data=self._request_security_approval("set_setting", context, {"setting_key": key, "new_value": value}).get("data"),
                metadata={"method": "update_setting"},
            )

        normalized_key = _normalize_key(key)
        current_settings = _dataclass_to_dict(self.settings)

        if normalized_key not in current_settings:
            return self._error_result(
                f"Unknown Business Agent setting: {key}",
                error="unknown_setting",
                metadata={"method": "update_setting", "requested_key": key},
            )

        safe_value = self._coerce_setting_value(normalized_key, value)
        current_settings[normalized_key] = safe_value
        current_settings["metadata"] = dict(current_settings.get("metadata") or {})
        current_settings["metadata"]["updated_at"] = _utc_now_iso()
        current_settings["metadata"]["updated_by_user_id"] = validation["data"].get("user_id")

        self.settings = BusinessAgentSettings(**current_settings)

        result = self._safe_result(
            "Business Agent setting updated.",
            data={"key": normalized_key, "value": safe_value},
            metadata={
                "method": "update_setting",
                "verification": self._prepare_verification_payload("update_setting", context),
                "memory": self._prepare_memory_payload(
                    "update_setting",
                    context,
                    summary=f"Business Agent setting updated: {normalized_key}",
                    data={"key": normalized_key, "value": safe_value},
                ),
            },
        )

        self._log_audit_event(
            "update_setting",
            context,
            {"setting_key": normalized_key, "new_value": safe_value},
            success=True,
        )
        self._emit_agent_event("business_config_setting_updated", context, {"setting_key": normalized_key})

        return result

    # ------------------------------------------------------------------
    # Public CRM Provider Methods
    # ------------------------------------------------------------------

    def list_crm_providers(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """List configured CRM providers."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to list CRM provider configuration.",
                error="permission_denied",
                metadata={"method": "list_crm_providers"},
            )

        providers = [
            self._public_crm_provider_dict(provider_config)
            for provider_config in self._crm_providers.values()
        ]

        return self._safe_result(
            "CRM provider configurations loaded.",
            data={
                "providers": providers,
                "default_provider": self.settings.default_crm_provider,
                "count": len(providers),
            },
            metadata={"method": "list_crm_providers"},
        )

    def get_crm_provider_config(
        self,
        provider: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return one CRM provider configuration."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to read CRM provider configuration.",
                error="permission_denied",
                metadata={"method": "get_crm_provider_config"},
            )

        provider_key = _normalize_key(provider or self.settings.default_crm_provider)
        provider_config = self._crm_providers.get(provider_key)

        if not provider_config:
            return self._error_result(
                f"CRM provider is not configured: {provider or self.settings.default_crm_provider}",
                error="unknown_crm_provider",
                metadata={"method": "get_crm_provider_config", "provider": provider_key},
            )

        return self._safe_result(
            "CRM provider configuration loaded.",
            data=self._public_crm_provider_dict(provider_config),
            metadata={"method": "get_crm_provider_config", "provider": provider_key},
        )

    def get_enabled_crm_providers(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return enabled CRM providers only."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to read CRM provider configuration.",
                error="permission_denied",
                metadata={"method": "get_enabled_crm_providers"},
            )

        providers = [
            self._public_crm_provider_dict(provider_config)
            for provider_config in self._crm_providers.values()
            if provider_config.enabled
        ]

        return self._safe_result(
            "Enabled CRM providers loaded.",
            data={"providers": providers, "count": len(providers)},
            metadata={"method": "get_enabled_crm_providers"},
        )

    def upsert_crm_provider(
        self,
        provider_config: CRMProviderConfig | Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Create or update an in-memory CRM provider definition.

        This only changes runtime config. It does not store secrets and does not
        connect to external CRM APIs.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        permission = self.has_permission(context, BusinessPermission.MANAGE_CRM_PROVIDERS.value)
        if not permission.get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to manage CRM provider configuration.",
                error="permission_denied",
                metadata={"method": "upsert_crm_provider"},
            )

        if self._requires_security_check("upsert_crm_provider", context, {"external_provider_write": True}) and not security_approved:
            return self._error_result(
                "Security approval is required before changing CRM provider configuration.",
                error="security_approval_required",
                data=self._request_security_approval("upsert_crm_provider", context, {"provider_config": provider_config}).get("data"),
                metadata={"method": "upsert_crm_provider"},
            )

        config_result = self._coerce_crm_provider_config(provider_config)
        if not config_result.get("success"):
            return config_result

        config = config_result["data"]
        self._crm_providers[config.provider] = config

        result = self._safe_result(
            "CRM provider configuration saved.",
            data=self._public_crm_provider_dict(config),
            metadata={
                "method": "upsert_crm_provider",
                "verification": self._prepare_verification_payload("upsert_crm_provider", context),
                "memory": self._prepare_memory_payload(
                    "upsert_crm_provider",
                    context,
                    summary=f"CRM provider configuration updated: {config.provider}",
                    data={"provider": config.provider, "enabled": config.enabled},
                ),
            },
        )

        self._log_audit_event(
            "upsert_crm_provider",
            context,
            {"provider": config.provider, "enabled": config.enabled},
            success=True,
        )
        self._emit_agent_event("business_crm_provider_upserted", context, {"provider": config.provider})

        return result

    def enable_crm_provider(
        self,
        provider: str,
        context: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Enable a configured CRM provider."""

        return self._set_crm_provider_enabled(
            provider=provider,
            enabled=True,
            context=context,
            security_approved=security_approved,
            method_name="enable_crm_provider",
        )

    def disable_crm_provider(
        self,
        provider: str,
        context: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Disable a configured CRM provider."""

        return self._set_crm_provider_enabled(
            provider=provider,
            enabled=False,
            context=context,
            security_approved=security_approved,
            method_name="disable_crm_provider",
        )

    # ------------------------------------------------------------------
    # Public Report Period Methods
    # ------------------------------------------------------------------

    def list_report_periods(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """List report period presets."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_REPORTS.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to list report periods.",
                error="permission_denied",
                metadata={"method": "list_report_periods"},
            )

        periods = [_dataclass_to_dict(period) for period in self._report_periods.values()]

        return self._safe_result(
            "Report periods loaded.",
            data={
                "periods": periods,
                "default_period": self.settings.default_report_period,
                "count": len(periods),
            },
            metadata={"method": "list_report_periods"},
        )

    def get_report_period(
        self,
        period: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return one report period preset."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_REPORTS.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to read report period configuration.",
                error="permission_denied",
                metadata={"method": "get_report_period"},
            )

        period_key = _normalize_key(period or self.settings.default_report_period)
        period_config = self._report_periods.get(period_key)

        if not period_config:
            return self._error_result(
                f"Report period is not configured: {period or self.settings.default_report_period}",
                error="unknown_report_period",
                metadata={"method": "get_report_period", "period": period_key},
            )

        return self._safe_result(
            "Report period loaded.",
            data=_dataclass_to_dict(period_config),
            metadata={"method": "get_report_period", "period": period_key},
        )

    def validate_report_period_request(
        self,
        period: str,
        context: Optional[Mapping[str, Any]] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate a report period request for dashboards/report builder."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        period_result = self.get_report_period(period, context)
        if not period_result.get("success"):
            return period_result

        period_data = period_result["data"]

        if period_data.get("requires_custom_dates"):
            if not start_date or not end_date:
                return self._error_result(
                    "Custom report period requires start_date and end_date.",
                    error="missing_custom_date_range",
                    metadata={"method": "validate_report_period_request", "period": period},
                )

            date_validation = self._validate_date_pair(start_date, end_date)
            if not date_validation.get("success"):
                return date_validation

        return self._safe_result(
            "Report period request is valid.",
            data={
                "period": period_data,
                "start_date": start_date,
                "end_date": end_date,
            },
            metadata={"method": "validate_report_period_request"},
        )

    # ------------------------------------------------------------------
    # Public Role/Permission Methods
    # ------------------------------------------------------------------

    def list_role_rules(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """List Business Agent role rules."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to list Business Agent role rules.",
                error="permission_denied",
                metadata={"method": "list_role_rules"},
            )

        roles = [_dataclass_to_dict(role_rule) for role_rule in self._role_rules.values()]

        return self._safe_result(
            "Business Agent role rules loaded.",
            data={"roles": roles, "count": len(roles)},
            metadata={"method": "list_role_rules"},
        )

    def get_role_rule(
        self,
        role: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return one Business Agent role rule."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        normalized_role = _normalize_key(role)
        role_rule = self._role_rules.get(normalized_role)

        if not role_rule:
            return self._error_result(
                f"Business Agent role is not configured: {role}",
                error="unknown_business_role",
                metadata={"method": "get_role_rule", "role": normalized_role},
            )

        return self._safe_result(
            "Business Agent role rule loaded.",
            data=_dataclass_to_dict(role_rule),
            metadata={"method": "get_role_rule", "role": normalized_role},
        )

    def has_permission(
        self,
        context: Optional[Mapping[str, Any]],
        permission: str,
    ) -> Dict[str, Any]:
        """
        Check whether the context role has a specific Business Agent permission.

        This is role-based and workspace-local. Object-level ownership checks should
        be performed by the relevant business submodule using user_id/workspace_id.
        """

        if context is None:
            return self._safe_result(
                "No context supplied; permission denied.",
                data={"allowed": False, "reason": "missing_context"},
                metadata={"method": "has_permission"},
            )

        role = _normalize_key(context.get("role") or BusinessRole.VIEWER.value) or BusinessRole.VIEWER.value
        normalized_permission = str(permission).strip()

        role_rule = self._role_rules.get(role)
        if not role_rule:
            return self._safe_result(
                "Unknown role; permission denied.",
                data={"allowed": False, "role": role, "permission": normalized_permission, "reason": "unknown_role"},
                metadata={"method": "has_permission"},
            )

        allowed = normalized_permission in set(role_rule.permissions)

        return self._safe_result(
            "Permission check completed.",
            data={
                "allowed": allowed,
                "role": role,
                "permission": normalized_permission,
                "reason": "allowed" if allowed else "permission_not_granted",
            },
            metadata={"method": "has_permission"},
        )

    def require_permission(
        self,
        context: Optional[Mapping[str, Any]],
        permission: str,
    ) -> Dict[str, Any]:
        """Require a permission and return an error result when denied."""

        check = self.has_permission(context, permission)
        allowed = check.get("data", {}).get("allowed")

        if allowed:
            return self._safe_result(
                "Permission granted.",
                data=check.get("data"),
                metadata={"method": "require_permission"},
            )

        return self._error_result(
            "Permission denied.",
            error="permission_denied",
            data=check.get("data"),
            metadata={"method": "require_permission"},
        )

    def update_role_rule(
        self,
        role_rule: RoleRule | Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Create or update a role rule.

        Role changes are sensitive and require Security Agent approval.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        permission = self.has_permission(context, BusinessPermission.MANAGE_ROLE_RULES.value)
        if not permission.get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to manage Business Agent role rules.",
                error="permission_denied",
                metadata={"method": "update_role_rule"},
            )

        if self._requires_security_check("update_role_rule", context, {"contains_sensitive_data": True}) and not security_approved:
            return self._error_result(
                "Security approval is required before changing role rules.",
                error="security_approval_required",
                data=self._request_security_approval("update_role_rule", context, {"role_rule": role_rule}).get("data"),
                metadata={"method": "update_role_rule"},
            )

        role_result = self._coerce_role_rule(role_rule)
        if not role_result.get("success"):
            return role_result

        role_config = role_result["data"]
        self._role_rules[role_config.role] = role_config

        result = self._safe_result(
            "Business Agent role rule saved.",
            data=_dataclass_to_dict(role_config),
            metadata={
                "method": "update_role_rule",
                "verification": self._prepare_verification_payload("update_role_rule", context),
                "memory": self._prepare_memory_payload(
                    "update_role_rule",
                    context,
                    summary=f"Business Agent role rule updated: {role_config.role}",
                    data={"role": role_config.role, "permissions_count": len(role_config.permissions)},
                ),
            },
        )

        self._log_audit_event(
            "update_role_rule",
            context,
            {"role": role_config.role, "permissions_count": len(role_config.permissions)},
            success=True,
        )
        self._emit_agent_event("business_role_rule_updated", context, {"role": role_config.role})

        return result

    # ------------------------------------------------------------------
    # Public Validation/Manifest Methods
    # ------------------------------------------------------------------

    def validate_configuration(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Validate the full Business Agent configuration."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        errors: List[str] = []
        warnings: List[str] = []

        if self.settings.default_crm_provider not in self._crm_providers:
            errors.append(f"default_crm_provider is not configured: {self.settings.default_crm_provider}")

        if self.settings.default_report_period not in self._report_periods:
            errors.append(f"default_report_period is not configured: {self.settings.default_report_period}")

        if self.settings.max_export_rows < self.settings.max_report_rows:
            warnings.append("max_export_rows is lower than max_report_rows.")

        for provider_key, provider_config in self._crm_providers.items():
            if provider_key != provider_config.provider:
                warnings.append(f"CRM provider key differs from provider value: {provider_key} != {provider_config.provider}")

            if provider_config.enabled and provider_config.auth_type != "internal":
                missing_secret_names = [
                    name for name in provider_config.secret_env_keys if not os.getenv(name)
                ]
                if missing_secret_names:
                    warnings.append(
                        f"Enabled CRM provider '{provider_key}' has missing environment/secret keys: "
                        f"{', '.join(missing_secret_names)}"
                    )

        for role_key, role_rule in self._role_rules.items():
            if role_key != role_rule.role:
                warnings.append(f"Role key differs from role value: {role_key} != {role_rule.role}")

            invalid_permissions = [
                permission
                for permission in role_rule.permissions
                if permission not in {item.value for item in BusinessPermission}
            ]
            if invalid_permissions:
                warnings.append(
                    f"Role '{role_key}' has non-standard permissions: {', '.join(invalid_permissions)}"
                )

        success = not errors

        result_data = {
            "valid": success,
            "errors": errors,
            "warnings": warnings,
            "crm_provider_count": len(self._crm_providers),
            "report_period_count": len(self._report_periods),
            "role_rule_count": len(self._role_rules),
            "validated_at": _utc_now_iso(),
        }

        if success:
            return self._safe_result(
                "Business Agent configuration is valid.",
                data=result_data,
                metadata={"method": "validate_configuration"},
            )

        return self._error_result(
            "Business Agent configuration validation failed.",
            error="invalid_business_configuration",
            data=result_data,
            metadata={"method": "validate_configuration"},
        )

    def registry_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry/Loader-compatible metadata.

        This allows future registry systems to inspect this module without needing
        external dependencies.
        """

        return {
            "success": True,
            "message": "BusinessConfig registry manifest loaded.",
            "data": {
                "agent": AGENT_NAME,
                "module": MODULE_NAME,
                "class_name": REQUIRED_CLASS_NAME,
                "config_version": CONFIG_VERSION,
                "import_safe": True,
                "uses_external_services": False,
                "hardcodes_secrets": False,
                "supports_user_workspace_isolation": True,
                "supports_security_hook": True,
                "supports_verification_payload": True,
                "supports_memory_payload": True,
                "public_methods": [
                    "get_settings",
                    "get_setting",
                    "update_setting",
                    "list_crm_providers",
                    "get_crm_provider_config",
                    "get_enabled_crm_providers",
                    "upsert_crm_provider",
                    "enable_crm_provider",
                    "disable_crm_provider",
                    "list_report_periods",
                    "get_report_period",
                    "validate_report_period_request",
                    "list_role_rules",
                    "get_role_rule",
                    "has_permission",
                    "require_permission",
                    "update_role_rule",
                    "validate_configuration",
                    "registry_manifest",
                    "dashboard_payload",
                ],
            },
            "error": None,
            "metadata": self._base_metadata({"method": "registry_manifest"}),
        }

    def dashboard_payload(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """
        Return Dashboard/API-friendly Business Agent config summary.

        Sensitive values and secret contents are never included.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        if not self.has_permission(context, BusinessPermission.READ_CONFIG.value).get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to view Business Agent dashboard configuration.",
                error="permission_denied",
                metadata={"method": "dashboard_payload"},
            )

        enabled_providers = [
            provider.provider
            for provider in self._crm_providers.values()
            if provider.enabled
        ]

        payload = {
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "config_version": CONFIG_VERSION,
            "settings": {
                "default_crm_provider": self.settings.default_crm_provider,
                "default_report_period": self.settings.default_report_period,
                "default_currency": self.settings.default_currency,
                "default_timezone": self.settings.default_timezone,
                "max_report_rows": self.settings.max_report_rows,
                "max_export_rows": self.settings.max_export_rows,
            },
            "crm": {
                "default_provider": self.settings.default_crm_provider,
                "enabled_providers": enabled_providers,
                "provider_count": len(self._crm_providers),
            },
            "reports": {
                "default_period": self.settings.default_report_period,
                "period_count": len(self._report_periods),
            },
            "roles": {
                "role_count": len(self._role_rules),
                "available_roles": list(self._role_rules.keys()),
            },
            "safety": {
                "require_security_for_exports": self.settings.require_security_for_exports,
                "require_security_for_deletes": self.settings.require_security_for_deletes,
                "require_security_for_provider_changes": self.settings.require_security_for_provider_changes,
                "require_security_for_role_changes": self.settings.require_security_for_role_changes,
                "secrets_exposed": False,
            },
        }

        return self._safe_result(
            "Business Agent dashboard config payload prepared.",
            data=payload,
            metadata={"method": "dashboard_payload"},
        )

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _base_metadata(self, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Build base metadata for all structured results."""

        base = {
            "agent": AGENT_NAME,
            "module": MODULE_NAME,
            "config_version": CONFIG_VERSION,
            "timestamp": _utc_now_iso(),
        }

        if metadata:
            base.update(dict(metadata))

        return base

    def _public_crm_provider_dict(self, provider_config: CRMProviderConfig) -> Dict[str, Any]:
        """
        Convert CRM provider config to a public JSON-safe dict.

        Secret values are never included. Only expected secret key names are shown.
        """

        data = _dataclass_to_dict(provider_config)
        data["secret_env_keys"] = list(provider_config.secret_env_keys)
        data["secrets_present"] = {
            key: bool(os.getenv(key))
            for key in provider_config.secret_env_keys
        }
        data["secret_values_exposed"] = False
        return data

    def _redact_sensitive_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Redact secret-like fields from payloads before audit/event/memory output."""

        sensitive_terms = {
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "authorization",
            "client_secret",
            "private_key",
            "credential",
            "credentials",
        }

        def redact(value: Any, key_path: str = "") -> Any:
            key_name = key_path.split(".")[-1].lower()

            if any(term in key_name for term in sensitive_terms):
                return "***REDACTED***"

            if isinstance(value, Mapping):
                return {
                    str(k): redact(v, f"{key_path}.{k}" if key_path else str(k))
                    for k, v in value.items()
                }

            if isinstance(value, list):
                return [redact(item, key_path) for item in value]

            if isinstance(value, tuple):
                return [redact(item, key_path) for item in value]

            if isinstance(value, CRMProviderConfig):
                return self._public_crm_provider_dict(value)

            if isinstance(value, RoleRule):
                return _dataclass_to_dict(value)

            if isinstance(value, ReportPeriodConfig):
                return _dataclass_to_dict(value)

            if isinstance(value, BusinessAgentSettings):
                return _dataclass_to_dict(value)

            return value

        return redact(dict(payload))

    def _coerce_setting_value(self, key: str, value: Any) -> Any:
        """Coerce setting values to the expected type for BusinessAgentSettings."""

        bool_keys = {
            "enable_audit_logging",
            "enable_agent_events",
            "enable_memory_payloads",
            "enable_verification_payloads",
            "enable_dashboard_metadata",
            "require_security_for_exports",
            "require_security_for_deletes",
            "require_security_for_provider_changes",
            "require_security_for_role_changes",
            "require_workspace_id",
            "require_user_id",
        }

        int_keys = {
            "max_report_rows",
            "max_export_rows",
            "max_bulk_update_records",
            "crm_request_timeout_seconds",
            "crm_retry_attempts",
            "memory_payload_max_chars",
        }

        if key in bool_keys:
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return bool(value)

        if key in int_keys:
            coerced = int(value)
            if coerced < 0:
                raise ValueError(f"{key} cannot be negative")
            return coerced

        if key == "default_currency":
            return str(value).strip().upper() or "USD"

        if key in {"default_crm_provider", "default_report_period"}:
            return _normalize_key(value)

        if key == "metadata":
            return dict(value or {})

        return str(value).strip() if isinstance(value, str) else value

    def _coerce_crm_provider_config(
        self,
        provider_config: CRMProviderConfig | Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Validate and coerce CRM provider config input."""

        if isinstance(provider_config, CRMProviderConfig):
            if not provider_config.provider:
                return self._error_result(
                    "CRM provider config requires provider key.",
                    error="invalid_crm_provider_config",
                    metadata={"method": "_coerce_crm_provider_config"},
                )
            return self._safe_result(
                "CRM provider config accepted.",
                data=provider_config,
                metadata={"method": "_coerce_crm_provider_config"},
            )

        if not isinstance(provider_config, Mapping):
            return self._error_result(
                "CRM provider config must be a mapping or CRMProviderConfig.",
                error="invalid_crm_provider_config",
                metadata={"method": "_coerce_crm_provider_config"},
            )

        data = dict(provider_config)
        provider_key = _normalize_key(data.get("provider"))
        if not provider_key:
            return self._error_result(
                "CRM provider config requires provider key.",
                error="missing_provider_key",
                metadata={"method": "_coerce_crm_provider_config"},
            )

        data["provider"] = provider_key
        data["display_name"] = str(data.get("display_name") or provider_key).strip()
        data["enabled"] = bool(data.get("enabled", False))
        data["auth_type"] = str(data.get("auth_type") or "none").strip()
        data["base_url"] = data.get("base_url")
        data["api_version"] = data.get("api_version")
        data["required_scopes"] = tuple(str(item) for item in (data.get("required_scopes") or ()))
        data["secret_env_keys"] = tuple(str(item) for item in (data.get("secret_env_keys") or ()))
        data["rate_limit_per_minute"] = int(data.get("rate_limit_per_minute", 60))
        data["timeout_seconds"] = int(data.get("timeout_seconds", 30))
        data["supports_webhooks"] = bool(data.get("supports_webhooks", False))
        data["supports_contacts"] = bool(data.get("supports_contacts", True))
        data["supports_companies"] = bool(data.get("supports_companies", True))
        data["supports_deals"] = bool(data.get("supports_deals", True))
        data["supports_tasks"] = bool(data.get("supports_tasks", True))
        data["supports_notes"] = bool(data.get("supports_notes", True))
        data["supports_custom_fields"] = bool(data.get("supports_custom_fields", True))
        data["requires_security_approval_for_write"] = bool(data.get("requires_security_approval_for_write", True))
        data["requires_workspace_mapping"] = bool(data.get("requires_workspace_mapping", True))
        data["metadata"] = dict(data.get("metadata") or {})

        if data["rate_limit_per_minute"] <= 0:
            return self._error_result(
                "CRM provider rate_limit_per_minute must be greater than zero.",
                error="invalid_rate_limit",
                metadata={"method": "_coerce_crm_provider_config"},
            )

        if data["timeout_seconds"] <= 0:
            return self._error_result(
                "CRM provider timeout_seconds must be greater than zero.",
                error="invalid_timeout",
                metadata={"method": "_coerce_crm_provider_config"},
            )

        try:
            config = CRMProviderConfig(**data)
        except TypeError as exc:
            return self._error_result(
                "CRM provider config contains unsupported fields.",
                error="invalid_crm_provider_fields",
                data={"detail": str(exc)},
                metadata={"method": "_coerce_crm_provider_config"},
            )

        return self._safe_result(
            "CRM provider config validated.",
            data=config,
            metadata={"method": "_coerce_crm_provider_config"},
        )

    def _coerce_role_rule(self, role_rule: RoleRule | Mapping[str, Any]) -> Dict[str, Any]:
        """Validate and coerce role rule input."""

        if isinstance(role_rule, RoleRule):
            if not role_rule.role:
                return self._error_result(
                    "Role rule requires role key.",
                    error="invalid_role_rule",
                    metadata={"method": "_coerce_role_rule"},
                )
            return self._safe_result(
                "Role rule accepted.",
                data=role_rule,
                metadata={"method": "_coerce_role_rule"},
            )

        if not isinstance(role_rule, Mapping):
            return self._error_result(
                "Role rule must be a mapping or RoleRule.",
                error="invalid_role_rule",
                metadata={"method": "_coerce_role_rule"},
            )

        data = dict(role_rule)
        role_key = _normalize_key(data.get("role"))

        if not role_key:
            return self._error_result(
                "Role rule requires role key.",
                error="missing_role_key",
                metadata={"method": "_coerce_role_rule"},
            )

        permissions = tuple(str(item).strip() for item in (data.get("permissions") or ()) if str(item).strip())

        data["role"] = role_key
        data["label"] = str(data.get("label") or role_key).strip()
        data["permissions"] = permissions
        data["can_manage_lower_roles"] = bool(data.get("can_manage_lower_roles", False))
        data["can_access_all_workspace_records"] = bool(data.get("can_access_all_workspace_records", False))
        data["can_export_sensitive_data"] = bool(data.get("can_export_sensitive_data", False))
        data["requires_security_approval_for_sensitive_actions"] = bool(
            data.get("requires_security_approval_for_sensitive_actions", True)
        )
        data["description"] = str(data.get("description") or "").strip()

        if not permissions:
            return self._error_result(
                "Role rule requires at least one permission.",
                error="missing_role_permissions",
                metadata={"method": "_coerce_role_rule"},
            )

        try:
            config = RoleRule(**data)
        except TypeError as exc:
            return self._error_result(
                "Role rule contains unsupported fields.",
                error="invalid_role_rule_fields",
                data={"detail": str(exc)},
                metadata={"method": "_coerce_role_rule"},
            )

        return self._safe_result(
            "Role rule validated.",
            data=config,
            metadata={"method": "_coerce_role_rule"},
        )

    def _set_crm_provider_enabled(
        self,
        *,
        provider: str,
        enabled: bool,
        context: Optional[Mapping[str, Any]],
        security_approved: bool,
        method_name: str,
    ) -> Dict[str, Any]:
        """Enable or disable a CRM provider."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        permission = self.has_permission(context, BusinessPermission.MANAGE_CRM_PROVIDERS.value)
        if not permission.get("data", {}).get("allowed"):
            return self._error_result(
                "Role is not allowed to manage CRM provider configuration.",
                error="permission_denied",
                metadata={"method": method_name},
            )

        if self._requires_security_check(method_name, context, {"provider": provider}) and not security_approved:
            return self._error_result(
                "Security approval is required before changing CRM provider status.",
                error="security_approval_required",
                data=self._request_security_approval(method_name, context, {"provider": provider, "enabled": enabled}).get("data"),
                metadata={"method": method_name},
            )

        provider_key = _normalize_key(provider)
        existing = self._crm_providers.get(provider_key)

        if not existing:
            return self._error_result(
                f"CRM provider is not configured: {provider}",
                error="unknown_crm_provider",
                metadata={"method": method_name, "provider": provider_key},
            )

        data = _dataclass_to_dict(existing)
        data["enabled"] = bool(enabled)
        updated = CRMProviderConfig(
            provider=data["provider"],
            display_name=data["display_name"],
            enabled=data["enabled"],
            auth_type=data["auth_type"],
            base_url=data["base_url"],
            api_version=data["api_version"],
            required_scopes=tuple(data["required_scopes"]),
            secret_env_keys=tuple(data["secret_env_keys"]),
            rate_limit_per_minute=data["rate_limit_per_minute"],
            timeout_seconds=data["timeout_seconds"],
            supports_webhooks=data["supports_webhooks"],
            supports_contacts=data["supports_contacts"],
            supports_companies=data["supports_companies"],
            supports_deals=data["supports_deals"],
            supports_tasks=data["supports_tasks"],
            supports_notes=data["supports_notes"],
            supports_custom_fields=data["supports_custom_fields"],
            requires_security_approval_for_write=data["requires_security_approval_for_write"],
            requires_workspace_mapping=data["requires_workspace_mapping"],
            metadata=dict(data.get("metadata") or {}),
        )

        self._crm_providers[provider_key] = updated

        result = self._safe_result(
            f"CRM provider {'enabled' if enabled else 'disabled'}.",
            data=self._public_crm_provider_dict(updated),
            metadata={
                "method": method_name,
                "verification": self._prepare_verification_payload(method_name, context),
            },
        )

        self._log_audit_event(
            method_name,
            context,
            {"provider": provider_key, "enabled": enabled},
            success=True,
        )
        self._emit_agent_event(
            "business_crm_provider_status_changed",
            context,
            {"provider": provider_key, "enabled": enabled},
        )

        return result

    def _validate_date_pair(self, start_date: str, end_date: str) -> Dict[str, Any]:
        """Validate YYYY-MM-DD date pair."""

        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
        except ValueError:
            return self._error_result(
                "start_date and end_date must be valid ISO date/datetime strings.",
                error="invalid_date_format",
                metadata={"method": "_validate_date_pair"},
            )

        if start > end:
            return self._error_result(
                "start_date must be before or equal to end_date.",
                error="invalid_date_range",
                metadata={"method": "_validate_date_pair"},
            )

        return self._safe_result(
            "Date range is valid.",
            data={"start_date": start_date, "end_date": end_date},
            metadata={"method": "_validate_date_pair"},
        )


# ---------------------------------------------------------------------------
# Module-Level Convenience Factory
# ---------------------------------------------------------------------------


def get_business_config() -> BusinessConfig:
    """
    Return a new BusinessConfig instance.

    Keeping this as a factory avoids global mutable shared state across tests,
    users, workers, and workspaces.
    """

    return BusinessConfig()


def registry_manifest() -> Dict[str, Any]:
    """Module-level registry manifest helper."""

    return BusinessConfig().registry_manifest()


__all__ = [
    "BusinessConfig",
    "BusinessAgentSettings",
    "CRMProviderConfig",
    "ReportPeriodConfig",
    "RoleRule",
    "BusinessRole",
    "CRMProvider",
    "ReportPeriod",
    "BusinessPermission",
    "SecurityAction",
    "get_business_config",
    "registry_manifest",
    "CONFIG_VERSION",
    "MODULE_NAME",
    "AGENT_NAME",
]