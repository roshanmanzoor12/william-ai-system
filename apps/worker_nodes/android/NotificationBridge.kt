package com.digitalpromotix.william.worker.android

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.text.TextUtils
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Device Worker Prompt Bible
 *
 * File:
 *      apps/worker_nodes/android/NotificationBridge.kt
 *
 * Required class/component name:
 *      Notificationbridge
 *
 * Purpose:
 *      Android notification-access bridge with explicit permission handling.
 *
 * What this service does:
 *      - Integrates with Android Notification Listener permission.
 *      - Captures notification posted / removed events after the user grants access.
 *      - Enforces user_id + workspace_id isolation for every worker task.
 *      - Supports worker registration, heartbeat, task polling, stop/resume.
 *      - Applies role/plan checks for dashboard/API exposed functionality.
 *      - Redacts sensitive notification content by default.
 *      - Prepares Security Agent payloads for sensitive actions.
 *      - Prepares Verification Agent payloads after completed actions.
 *      - Prepares Memory Agent compatible summaries.
 *      - Emits safe broadcast reports for the Android worker host app.
 *
 * AndroidManifest.xml requirement:
 *
 * <service
 *     android:name=".Notificationbridge"
 *     android:label="William Notification Bridge"
 *     android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
 *     android:exported="true">
 *     <intent-filter>
 *         <action android:name="android.service.notification.NotificationListenerService" />
 *     </intent-filter>
 * </service>
 *
 * Security notes:
 *      - This service does not send network requests directly.
 *      - The host worker app should receive ACTION_NOTIFICATION_REPORT broadcasts
 *        and forward them to the backend only after its own authenticated checks.
 *      - Raw notification text is redacted unless policy allows sensitive content
 *        and Security Agent approval has been recorded.
 *      - No secrets are hardcoded.
 */
class Notificationbridge : NotificationListenerService() {

    enum class WorkerState(val value: String) {
        READY("ready"),
        BUSY("busy"),
        PAUSED("paused"),
        STOPPED("stopped"),
        ERROR("error")
    }

    enum class BridgeAction(val value: String) {
        REGISTER_DEVICE("register_device"),
        HEARTBEAT("heartbeat"),
        STOP("stop"),
        RESUME("resume"),
        OPEN_PERMISSION_SETTINGS("open_permission_settings"),
        GET_RECENT_NOTIFICATIONS("get_recent_notifications"),
        CLEAR_RECENT_NOTIFICATIONS("clear_recent_notifications"),
        UPDATE_POLICY("update_policy"),
        NOTIFICATION_POSTED("notification_posted"),
        NOTIFICATION_REMOVED("notification_removed"),
        PERMISSION_CHANGED("permission_changed")
    }

    enum class ActionStatus(val value: String) {
        SUCCESS("success"),
        ERROR("error"),
        DENIED("denied"),
        SECURITY_REVIEW_REQUIRED("security_review_required"),
        PERMISSION_REQUIRED("permission_required"),
        SKIPPED("skipped")
    }

    enum class RiskLevel(val value: String) {
        LOW("low"),
        MEDIUM("medium"),
        HIGH("high"),
        CRITICAL("critical")
    }

    data class TaskContext(
        val userId: String,
        val workspaceId: String,
        val taskId: String,
        val requestedBy: String,
        val role: String,
        val plan: String,
        val agentName: String,
        val correlationId: String
    ) {
        fun validate(): TaskContext {
            val safeUserId = userId.safeTrim(128)
            val safeWorkspaceId = workspaceId.safeTrim(128)

            require(safeUserId.isNotBlank()) {
                "user_id is required for NotificationBridge task isolation."
            }
            require(safeWorkspaceId.isNotBlank()) {
                "workspace_id is required for NotificationBridge task isolation."
            }

            return copy(
                userId = safeUserId,
                workspaceId = safeWorkspaceId,
                taskId = taskId.safeTrim(128).ifBlank { generateId("task") },
                requestedBy = requestedBy.safeTrim(128).ifBlank { safeUserId },
                role = role.safeTrim(80).ifBlank { "owner" },
                plan = plan.safeTrim(80).ifBlank { "pro" },
                agentName = agentName.safeTrim(120).ifBlank { "AndroidWorker" },
                correlationId = correlationId.safeTrim(128).ifBlank { generateId("corr") }
            )
        }
    }

    data class AccessDecision(
        val allowed: Boolean,
        val reason: String,
        val role: String,
        val plan: String,
        val action: String
    )

    data class BridgePolicy(
        val allowSensitiveContent: Boolean,
        val allowPackageNames: Set<String>,
        val blockPackageNames: Set<String>,
        val maxRecentEvents: Int
    )

    private val running = AtomicBoolean(true)

    override fun onCreate() {
        super.onCreate()
        saveWorkerState(this, WorkerState.READY)
        emitLifecycleReport(BridgeAction.PERMISSION_CHANGED, "Notification bridge service created.")
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        savePermissionState(this, true)
        saveWorkerState(this, WorkerState.READY)
        emitLifecycleReport(BridgeAction.PERMISSION_CHANGED, "Notification listener connected.")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        savePermissionState(this, false)
        emitLifecycleReport(BridgeAction.PERMISSION_CHANGED, "Notification listener disconnected.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        val registration = loadRegistration(this)
        if (registration == null) {
            storeUnregisteredEventSafely(sbn, BridgeAction.NOTIFICATION_POSTED)
            return
        }

        val state = getWorkerState(this)
        if (state == WorkerState.STOPPED || state == WorkerState.PAUSED) {
            val context = registrationToContext(registration, BridgeAction.NOTIFICATION_POSTED)
            val result = buildResult(
                status = ActionStatus.SKIPPED,
                action = BridgeAction.NOTIFICATION_POSTED,
                context = context,
                message = "Notification event skipped because worker is ${state.value}.",
                data = JSONObject()
                    .put("worker_state", state.value)
                    .put("package_name", sbn.packageName.safeTrim(200))
            )
            emitReport(this, result)
            return
        }

        val context = registrationToContext(registration, BridgeAction.NOTIFICATION_POSTED)
        val policy = loadPolicy(this)

        if (isPackageBlocked(sbn.packageName, policy)) {
            val result = buildResult(
                status = ActionStatus.SKIPPED,
                action = BridgeAction.NOTIFICATION_POSTED,
                context = context,
                message = "Notification skipped by package policy.",
                data = JSONObject()
                    .put("package_name", sbn.packageName.safeTrim(200))
                    .put("policy", policyToJson(policy, includePackages = true))
            )
            appendRecentEvent(this, result)
            emitReport(this, result)
            return
        }

        val notificationJson = extractNotificationJson(
            sbn = sbn,
            includeSensitive = policy.allowSensitiveContent
        )

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.NOTIFICATION_POSTED,
            context = context,
            message = "Notification posted event captured.",
            data = JSONObject()
                .put("notification", notificationJson)
                .put("policy", policyToJson(policy, includePackages = false))
        )

        appendRecentEvent(this, result)
        emitReport(this, result)
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        if (sbn == null) return

        val registration = loadRegistration(this) ?: return
        val context = registrationToContext(registration, BridgeAction.NOTIFICATION_REMOVED)

        val notificationJson = JSONObject()
            .put("package_name", sbn.packageName.safeTrim(200))
            .put("post_time", sbn.postTime)
            .put("key_hash", sha256(sbn.key ?: ""))
            .put("removed_at", isoNow())

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.NOTIFICATION_REMOVED,
            context = context,
            message = "Notification removed event captured.",
            data = JSONObject().put("notification", notificationJson)
        )

        appendRecentEvent(this, result)
        emitReport(this, result)
    }

    /**
     * Register this Android notification bridge for a user/workspace context.
     * The host app should call this after authentication and after user consent.
     */
    fun registerDevice(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro",
        requestedBy: String = userId,
        agentName: String = "AndroidWorker",
        metadata: JSONObject = JSONObject()
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("registration"),
            requestedBy = requestedBy,
            role = role,
            plan = plan,
            agentName = agentName,
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.REGISTER_DEVICE)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.REGISTER_DEVICE,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        val registration = JSONObject()
            .put("device_id", getOrCreateDeviceId(this))
            .put("worker_id", getOrCreateWorkerId(this))
            .put("user_id", context.userId)
            .put("workspace_id", context.workspaceId)
            .put("requested_by", context.requestedBy)
            .put("role", context.role)
            .put("plan", context.plan)
            .put("agent_name", context.agentName)
            .put("registered_at", isoNow())
            .put("android_sdk", Build.VERSION.SDK_INT)
            .put("manufacturer", Build.MANUFACTURER.safeTrim(120))
            .put("model", Build.MODEL.safeTrim(120))
            .put("package_name", packageName)
            .put("notification_access_enabled", isNotificationAccessEnabled(this))
            .put("metadata", sanitizeJson(metadata))

        prefs(this).edit()
            .putString(KEY_REGISTRATION, registration.toString())
            .apply()

        saveWorkerState(this, WorkerState.READY)

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.REGISTER_DEVICE,
            context = context,
            message = "Notification bridge registered.",
            data = JSONObject().put("registration", registration)
        )

        emitReport(this, result)
        return result
    }

    fun heartbeat(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro"
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("heartbeat"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.HEARTBEAT)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.HEARTBEAT,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        prefs(this).edit().putString(KEY_LAST_HEARTBEAT_AT, isoNow()).apply()

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.HEARTBEAT,
            context = context,
            message = "Notification bridge heartbeat healthy.",
            data = JSONObject()
                .put("device_id", getOrCreateDeviceId(this))
                .put("worker_id", getOrCreateWorkerId(this))
                .put("worker_state", getWorkerState(this).value)
                .put("running", running.get())
                .put("notification_access_enabled", isNotificationAccessEnabled(this))
                .put("android_sdk", Build.VERSION.SDK_INT)
                .put("manufacturer", Build.MANUFACTURER.safeTrim(120))
                .put("model", Build.MODEL.safeTrim(120))
                .put("package_name", packageName)
                .put("last_heartbeat_at", prefs(this).getString(KEY_LAST_HEARTBEAT_AT, null))
        )

        emitReport(this, result)
        return result
    }

    fun stopWorker(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro",
        reason: String? = null
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("stop"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.STOP)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.STOP,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        running.set(false)
        saveWorkerState(this, WorkerState.STOPPED)

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.STOP,
            context = context,
            message = "Notification bridge stopped safely.",
            data = JSONObject()
                .put("reason", reason.safeTrimOrNull(500))
                .put("worker_state", WorkerState.STOPPED.value)
        )

        emitReport(this, result)
        return result
    }

    fun resumeWorker(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro",
        reason: String? = null
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("resume"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.RESUME)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.RESUME,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        running.set(true)
        saveWorkerState(this, WorkerState.READY)

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.RESUME,
            context = context,
            message = "Notification bridge resumed safely.",
            data = JSONObject()
                .put("reason", reason.safeTrimOrNull(500))
                .put("worker_state", WorkerState.READY.value)
        )

        emitReport(this, result)
        return result
    }

    fun openNotificationPermissionSettings(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro"
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("permission"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.OPEN_PERMISSION_SETTINGS)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.OPEN_PERMISSION_SETTINGS,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        return try {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)

            val result = buildResult(
                status = ActionStatus.SUCCESS,
                action = BridgeAction.OPEN_PERMISSION_SETTINGS,
                context = context,
                message = "Notification access settings opened.",
                data = JSONObject()
                    .put("notification_access_enabled", isNotificationAccessEnabled(this))
            )

            emitReport(this, result)
            result
        } catch (error: Exception) {
            val result = safeErrorResult(
                action = BridgeAction.OPEN_PERMISSION_SETTINGS,
                context = context,
                message = "Unable to open notification access settings.",
                error = error
            )
            emitReport(this, result)
            result
        }
    }

    fun getRecentNotifications(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro"
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("recent"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.GET_RECENT_NOTIFICATIONS)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.GET_RECENT_NOTIFICATIONS,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.GET_RECENT_NOTIFICATIONS,
            context = context,
            message = "Recent notification events returned.",
            data = JSONObject()
                .put("events", loadRecentEvents(this))
                .put("count", loadRecentEvents(this).length())
        )

        emitReport(this, result)
        return result
    }

    fun clearRecentNotifications(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro",
        securityApproved: Boolean = false,
        reason: String? = null
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("clear"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.CLEAR_RECENT_NOTIFICATIONS)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.CLEAR_RECENT_NOTIFICATIONS,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        val security = securityGate(
            context = context,
            action = BridgeAction.CLEAR_RECENT_NOTIFICATIONS,
            riskLevel = RiskLevel.HIGH,
            securityApproved = securityApproved,
            reason = reason
        )

        if (!security.optBoolean("allowed", false)) {
            return buildResult(
                status = ActionStatus.SECURITY_REVIEW_REQUIRED,
                action = BridgeAction.CLEAR_RECENT_NOTIFICATIONS,
                context = context,
                message = security.optString("reason"),
                data = JSONObject().put("security", security)
            )
        }

        prefs(this).edit().putString(KEY_RECENT_EVENTS, JSONArray().toString()).apply()

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.CLEAR_RECENT_NOTIFICATIONS,
            context = context,
            message = "Recent notification events cleared.",
            data = JSONObject().put("reason", reason.safeTrimOrNull(500))
        )

        emitReport(this, result)
        return result
    }

    fun updatePolicy(
        userId: String,
        workspaceId: String,
        role: String = "owner",
        plan: String = "pro",
        allowSensitiveContent: Boolean = false,
        allowPackageNames: Set<String> = emptySet(),
        blockPackageNames: Set<String> = emptySet(),
        maxRecentEvents: Int = DEFAULT_MAX_RECENT_EVENTS,
        securityApproved: Boolean = false,
        reason: String? = null
    ): JSONObject {
        val context = TaskContext(
            userId = userId,
            workspaceId = workspaceId,
            taskId = generateId("policy"),
            requestedBy = userId,
            role = role,
            plan = plan,
            agentName = "AndroidWorker",
            correlationId = generateId("corr")
        ).validate()

        val access = checkAccess(context, BridgeAction.UPDATE_POLICY)
        if (!access.allowed) {
            return buildResult(
                status = ActionStatus.DENIED,
                action = BridgeAction.UPDATE_POLICY,
                context = context,
                message = access.reason,
                data = JSONObject().put("access", accessToJson(access))
            )
        }

        val risk = if (allowSensitiveContent) RiskLevel.CRITICAL else RiskLevel.MEDIUM
        val security = securityGate(
            context = context,
            action = BridgeAction.UPDATE_POLICY,
            riskLevel = risk,
            securityApproved = securityApproved,
            reason = reason
        )

        if (!security.optBoolean("allowed", false)) {
            return buildResult(
                status = ActionStatus.SECURITY_REVIEW_REQUIRED,
                action = BridgeAction.UPDATE_POLICY,
                context = context,
                message = security.optString("reason"),
                data = JSONObject().put("security", security)
            )
        }

        val boundedMax = maxRecentEvents.coerceIn(10, 500)
        val policy = BridgePolicy(
            allowSensitiveContent = allowSensitiveContent,
            allowPackageNames = allowPackageNames.map { it.safeTrim(200) }.filter { it.isNotBlank() }.toSet(),
            blockPackageNames = blockPackageNames.map { it.safeTrim(200) }.filter { it.isNotBlank() }.toSet(),
            maxRecentEvents = boundedMax
        )

        prefs(this).edit()
            .putBoolean(KEY_ALLOW_SENSITIVE_CONTENT, policy.allowSensitiveContent)
            .putStringSet(KEY_ALLOW_PACKAGES, policy.allowPackageNames)
            .putStringSet(KEY_BLOCK_PACKAGES, policy.blockPackageNames)
            .putInt(KEY_MAX_RECENT_EVENTS, policy.maxRecentEvents)
            .apply()

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = BridgeAction.UPDATE_POLICY,
            context = context,
            message = "Notification bridge policy updated.",
            data = JSONObject()
                .put("policy", policyToJson(policy, includePackages = true))
                .put("reason", reason.safeTrimOrNull(500))
        )

        emitReport(this, result)
        return result
    }

    /**
     * Poll/execute a task JSON from the Android worker host.
     */
    fun pollTask(task: JSONObject, securityApproved: Boolean = false): JSONObject {
        val action = task.optString("action").safeTrim(120).lowercase(Locale.US)
        val userId = task.optString("user_id").safeTrim(128)
        val workspaceId = task.optString("workspace_id").safeTrim(128)
        val role = task.optString("role", "owner").safeTrim(80)
        val plan = task.optString("plan", "pro").safeTrim(80)

        return try {
            when (action) {
                BridgeAction.REGISTER_DEVICE.value -> registerDevice(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan,
                    requestedBy = task.optString("requested_by", userId),
                    agentName = task.optString("agent_name", "AndroidWorker"),
                    metadata = task.optJSONObject("metadata") ?: JSONObject()
                )

                BridgeAction.HEARTBEAT.value -> heartbeat(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan
                )

                BridgeAction.STOP.value -> stopWorker(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan,
                    reason = task.optString("reason", null)
                )

                BridgeAction.RESUME.value -> resumeWorker(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan,
                    reason = task.optString("reason", null)
                )

                BridgeAction.OPEN_PERMISSION_SETTINGS.value -> openNotificationPermissionSettings(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan
                )

                BridgeAction.GET_RECENT_NOTIFICATIONS.value -> getRecentNotifications(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan
                )

                BridgeAction.CLEAR_RECENT_NOTIFICATIONS.value -> clearRecentNotifications(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan,
                    securityApproved = securityApproved,
                    reason = task.optString("reason", null)
                )

                BridgeAction.UPDATE_POLICY.value -> updatePolicy(
                    userId = userId,
                    workspaceId = workspaceId,
                    role = role,
                    plan = plan,
                    allowSensitiveContent = task.optBoolean("allow_sensitive_content", false),
                    allowPackageNames = jsonArrayToStringSet(task.optJSONArray("allow_package_names")),
                    blockPackageNames = jsonArrayToStringSet(task.optJSONArray("block_package_names")),
                    maxRecentEvents = task.optInt("max_recent_events", DEFAULT_MAX_RECENT_EVENTS),
                    securityApproved = securityApproved,
                    reason = task.optString("reason", null)
                )

                else -> {
                    val context = TaskContext(
                        userId = userId,
                        workspaceId = workspaceId,
                        taskId = task.optString("task_id", generateId("task")),
                        requestedBy = task.optString("requested_by", userId),
                        role = role,
                        plan = plan,
                        agentName = task.optString("agent_name", "AndroidWorker"),
                        correlationId = task.optString("correlation_id", generateId("corr"))
                    ).validate()

                    buildResult(
                        status = ActionStatus.ERROR,
                        action = BridgeAction.HEARTBEAT,
                        context = context,
                        message = "Unsupported NotificationBridge task action.",
                        data = JSONObject()
                            .put("received_action", action)
                            .put("supported_actions", JSONArray(BridgeAction.values().map { it.value }))
                    )
                }
            }
        } catch (error: Exception) {
            val fallbackContext = TaskContext(
                userId = userId,
                workspaceId = workspaceId,
                taskId = task.optString("task_id", generateId("task")),
                requestedBy = task.optString("requested_by", userId),
                role = role.ifBlank { "owner" },
                plan = plan.ifBlank { "pro" },
                agentName = task.optString("agent_name", "AndroidWorker"),
                correlationId = task.optString("correlation_id", generateId("corr"))
            ).validate()

            safeErrorResult(
                action = BridgeAction.HEARTBEAT,
                context = fallbackContext,
                message = "NotificationBridge task failed.",
                error = error
            )
        }
    }

    private fun extractNotificationJson(
        sbn: StatusBarNotification,
        includeSensitive: Boolean
    ): JSONObject {
        val notification = sbn.notification
        val extras = notification.extras

        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val subText = extras?.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
        val bigText = extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()

        val content = JSONObject()
            .put("title", if (includeSensitive) title.safeTrimOrNull(500) else redactIfPresent(title))
            .put("text", if (includeSensitive) text.safeTrimOrNull(1000) else redactIfPresent(text))
            .put("sub_text", if (includeSensitive) subText.safeTrimOrNull(500) else redactIfPresent(subText))
            .put("big_text", if (includeSensitive) bigText.safeTrimOrNull(2000) else redactIfPresent(bigText))

        return JSONObject()
            .put("package_name", sbn.packageName.safeTrim(200))
            .put("id", sbn.id)
            .put("tag", sbn.tag.safeTrimOrNull(200))
            .put("key_hash", sha256(sbn.key ?: ""))
            .put("post_time", sbn.postTime)
            .put("event_at", isoNow())
            .put("is_ongoing", sbn.isOngoing)
            .put("is_clearable", sbn.isClearable)
            .put("user_hash", sha256(sbn.user?.toString() ?: ""))
            .put("category", notification.category.safeTrimOrNull(100))
            .put("priority", notification.priority)
            .put("visibility", notification.visibility)
            .put("content_redacted", !includeSensitive)
            .put("content", content)
    }

    private fun checkAccess(context: TaskContext, action: BridgeAction): AccessDecision {
        val allowedRoles = getAllowedRoles()
        val allowedPlans = getAllowedPlans()

        val role = context.role.lowercase(Locale.US)
        val plan = context.plan.lowercase(Locale.US)

        if (!allowedRoles.contains(role)) {
            return AccessDecision(
                allowed = false,
                reason = "Role '${context.role}' is not allowed to use NotificationBridge.",
                role = context.role,
                plan = context.plan,
                action = action.value
            )
        }

        if (!allowedPlans.contains(plan)) {
            return AccessDecision(
                allowed = false,
                reason = "Plan '${context.plan}' is not allowed to use NotificationBridge.",
                role = context.role,
                plan = context.plan,
                action = action.value
            )
        }

        return AccessDecision(
            allowed = true,
            reason = "Permission granted.",
            role = context.role,
            plan = context.plan,
            action = action.value
        )
    }

    private fun securityGate(
        context: TaskContext,
        action: BridgeAction,
        riskLevel: RiskLevel,
        securityApproved: Boolean,
        reason: String?
    ): JSONObject {
        val requiresReview = riskLevel == RiskLevel.HIGH || riskLevel == RiskLevel.CRITICAL ||
            action == BridgeAction.CLEAR_RECENT_NOTIFICATIONS ||
            action == BridgeAction.UPDATE_POLICY

        if (requiresReview && !securityApproved) {
            return JSONObject()
                .put("allowed", false)
                .put("requires_security_review", true)
                .put("reason", "Security Agent approval required for ${action.value}.")
                .put(
                    "security_agent_payload",
                    JSONObject()
                        .put("event", "security.review.device_worker.notification_bridge")
                        .put("device_id", getOrCreateDeviceId(this))
                        .put("worker_id", getOrCreateWorkerId(this))
                        .put("user_id", context.userId)
                        .put("workspace_id", context.workspaceId)
                        .put("task_id", context.taskId)
                        .put("correlation_id", context.correlationId)
                        .put("requested_by", context.requestedBy)
                        .put("agent_name", context.agentName)
                        .put("action", action.value)
                        .put("risk_level", riskLevel.value)
                        .put("reason", reason.safeTrimOrNull(500))
                        .put("timestamp", isoNow())
                )
        }

        return JSONObject()
            .put("allowed", true)
            .put("requires_security_review", requiresReview)
            .put("reason", "Security gate passed.")
    }

    private fun buildResult(
        status: ActionStatus,
        action: BridgeAction,
        context: TaskContext,
        message: String,
        data: JSONObject
    ): JSONObject {
        val safeContext = context.validate()
        val safeData = sanitizeJson(data)

        val auditPayload = buildAuditPayload(status, action, safeContext, safeData)
        val memoryPayload = buildMemoryPayload(status, action, safeContext, message, safeData)
        val verificationPayload = buildVerificationPayload(status, action, safeContext, safeData)

        val result = JSONObject()
            .put("success", status == ActionStatus.SUCCESS)
            .put("status", status.value)
            .put("message", message.safeTrim(1000))
            .put("action", action.value)
            .put(
                "device",
                JSONObject()
                    .put("device_id", getOrCreateDeviceId(this))
                    .put("worker_id", getOrCreateWorkerId(this))
                    .put("android_sdk", Build.VERSION.SDK_INT)
                    .put("manufacturer", Build.MANUFACTURER.safeTrim(120))
                    .put("model", Build.MODEL.safeTrim(120))
                    .put("package_name", packageName)
                    .put("worker_state", getWorkerState(this).value)
                    .put("notification_access_enabled", isNotificationAccessEnabled(this))
            )
            .put(
                "context",
                JSONObject()
                    .put("user_id", safeContext.userId)
                    .put("workspace_id", safeContext.workspaceId)
                    .put("task_id", safeContext.taskId)
                    .put("requested_by", safeContext.requestedBy)
                    .put("role", safeContext.role)
                    .put("plan", safeContext.plan)
                    .put("agent_name", safeContext.agentName)
                    .put("correlation_id", safeContext.correlationId)
            )
            .put("data", safeData)
            .put("audit_payload", auditPayload)
            .put("memory_payload", memoryPayload)
            .put("verification_payload", verificationPayload)
            .put("timestamp", isoNow())

        result.put("result_hash", sha256(result.toString()))
        return result
    }

    private fun safeErrorResult(
        action: BridgeAction,
        context: TaskContext,
        message: String,
        error: Exception
    ): JSONObject {
        return buildResult(
            status = ActionStatus.ERROR,
            action = action,
            context = context,
            message = message,
            data = JSONObject()
                .put("error_type", error::class.java.simpleName)
                .put("error", error.message.safeTrimOrNull(1000))
        )
    }

    private fun buildAuditPayload(
        status: ActionStatus,
        action: BridgeAction,
        context: TaskContext,
        data: JSONObject
    ): JSONObject {
        return JSONObject()
            .put("event", "device_worker.notification_bridge.audit")
            .put("device_id", getOrCreateDeviceId(this))
            .put("worker_id", getOrCreateWorkerId(this))
            .put("user_id", context.userId)
            .put("workspace_id", context.workspaceId)
            .put("task_id", context.taskId)
            .put("correlation_id", context.correlationId)
            .put("requested_by", context.requestedBy)
            .put("agent_name", context.agentName)
            .put("action", action.value)
            .put("status", status.value)
            .put("data_hash", sha256(data.toString()))
            .put("timestamp", isoNow())
    }

    private fun buildMemoryPayload(
        status: ActionStatus,
        action: BridgeAction,
        context: TaskContext,
        message: String,
        data: JSONObject
    ): JSONObject {
        val notification = data.optJSONObject("notification")
        return JSONObject()
            .put("source", "android_notification_bridge")
            .put("type", "device_notification_event")
            .put("user_id", context.userId)
            .put("workspace_id", context.workspaceId)
            .put("task_id", context.taskId)
            .put("title", "Android notification bridge: ${action.value}")
            .put(
                "summary",
                JSONObject()
                    .put("action", action.value)
                    .put("status", status.value)
                    .put("message", message.safeTrim(500))
                    .put("package_name", notification?.optString("package_name"))
                    .put("content_redacted", notification?.optBoolean("content_redacted", true))
                    .put("device_id", getOrCreateDeviceId(this))
                    .put("worker_id", getOrCreateWorkerId(this))
            )
            .put("created_at", isoNow())
    }

    private fun buildVerificationPayload(
        status: ActionStatus,
        action: BridgeAction,
        context: TaskContext,
        data: JSONObject
    ): JSONObject {
        return JSONObject()
            .put("event", "verification.device_worker.notification_bridge")
            .put("verification_id", generateId("ver"))
            .put("user_id", context.userId)
            .put("workspace_id", context.workspaceId)
            .put("task_id", context.taskId)
            .put("correlation_id", context.correlationId)
            .put("action", action.value)
            .put("status", status.value)
            .put("success", status == ActionStatus.SUCCESS)
            .put("device_id", getOrCreateDeviceId(this))
            .put("worker_id", getOrCreateWorkerId(this))
            .put("evidence_hash", sha256(data.toString()))
            .put("prepared_at", isoNow())
    }

    private fun emitLifecycleReport(action: BridgeAction, message: String) {
        val registration = loadRegistration(this)
        val context = if (registration != null) {
            registrationToContext(registration, action)
        } else {
            TaskContext(
                userId = "unregistered",
                workspaceId = "unregistered",
                taskId = generateId("lifecycle"),
                requestedBy = "system",
                role = "system",
                plan = "internal",
                agentName = "NotificationBridge",
                correlationId = generateId("corr")
            )
        }

        val result = buildResult(
            status = ActionStatus.SUCCESS,
            action = action,
            context = context,
            message = message,
            data = JSONObject()
                .put("notification_access_enabled", isNotificationAccessEnabled(this))
                .put("worker_state", getWorkerState(this).value)
        )

        emitReport(this, result)
    }

    private fun storeUnregisteredEventSafely(
        sbn: StatusBarNotification,
        action: BridgeAction
    ) {
        val context = TaskContext(
            userId = "unregistered",
            workspaceId = "unregistered",
            taskId = generateId("notification"),
            requestedBy = "system",
            role = "system",
            plan = "internal",
            agentName = "NotificationBridge",
            correlationId = generateId("corr")
        )

        val result = buildResult(
            status = ActionStatus.SKIPPED,
            action = action,
            context = context,
            message = "Notification skipped because bridge is not registered to a user/workspace.",
            data = JSONObject()
                .put("package_name", sbn.packageName.safeTrim(200))
                .put("key_hash", sha256(sbn.key ?: ""))
                .put("content_redacted", true)
        )

        appendRecentEvent(this, result)
        emitReport(this, result)
    }

    private fun isPackageBlocked(packageName: String?, policy: BridgePolicy): Boolean {
        val pkg = packageName.safeTrimOrNull(200) ?: return true

        if (policy.blockPackageNames.contains(pkg)) return true

        if (policy.allowPackageNames.isNotEmpty() && !policy.allowPackageNames.contains(pkg)) {
            return true
        }

        return false
    }

    private fun policyToJson(policy: BridgePolicy, includePackages: Boolean): JSONObject {
        val json = JSONObject()
            .put("allow_sensitive_content", policy.allowSensitiveContent)
            .put("max_recent_events", policy.maxRecentEvents)

        if (includePackages) {
            json.put("allow_package_names", JSONArray(policy.allowPackageNames.toList()))
            json.put("block_package_names", JSONArray(policy.blockPackageNames.toList()))
        }

        return json
    }

    private fun loadPolicy(context: Context): BridgePolicy {
        val sp = prefs(context)
        return BridgePolicy(
            allowSensitiveContent = sp.getBoolean(KEY_ALLOW_SENSITIVE_CONTENT, false),
            allowPackageNames = sp.getStringSet(KEY_ALLOW_PACKAGES, emptySet()) ?: emptySet(),
            blockPackageNames = sp.getStringSet(KEY_BLOCK_PACKAGES, DEFAULT_BLOCK_PACKAGES) ?: DEFAULT_BLOCK_PACKAGES,
            maxRecentEvents = sp.getInt(KEY_MAX_RECENT_EVENTS, DEFAULT_MAX_RECENT_EVENTS).coerceIn(10, 500)
        )
    }

    private fun registrationToContext(registration: JSONObject, action: BridgeAction): TaskContext {
        return TaskContext(
            userId = registration.optString("user_id"),
            workspaceId = registration.optString("workspace_id"),
            taskId = generateId(action.value),
            requestedBy = registration.optString("requested_by", registration.optString("user_id")),
            role = registration.optString("role", "owner"),
            plan = registration.optString("plan", "pro"),
            agentName = registration.optString("agent_name", "AndroidWorker"),
            correlationId = generateId("corr")
        ).validate()
    }

    private fun appendRecentEvent(context: Context, event: JSONObject) {
        val policy = loadPolicy(context)
        val current = loadRecentEvents(context)
        val next = JSONArray()

        val compactEvent = JSONObject()
            .put("status", event.optString("status"))
            .put("action", event.optString("action"))
            .put("message", event.optString("message"))
            .put("context", event.optJSONObject("context"))
            .put("device", event.optJSONObject("device"))
            .put("data", event.optJSONObject("data"))
            .put("audit_payload", event.optJSONObject("audit_payload"))
            .put("memory_payload", event.optJSONObject("memory_payload"))
            .put("verification_payload", event.optJSONObject("verification_payload"))
            .put("timestamp", event.optString("timestamp"))
            .put("result_hash", event.optString("result_hash"))

        next.put(compactEvent)

        var index = 0
        while (index < current.length() && next.length() < policy.maxRecentEvents) {
            next.put(current.optJSONObject(index))
            index++
        }

        prefs(context).edit().putString(KEY_RECENT_EVENTS, next.toString()).apply()
    }

    private fun loadRecentEvents(context: Context): JSONArray {
        val raw = prefs(context).getString(KEY_RECENT_EVENTS, "[]") ?: "[]"
        return try {
            JSONArray(raw)
        } catch (_: Exception) {
            JSONArray()
        }
    }

    private fun loadRegistration(context: Context): JSONObject? {
        val raw = prefs(context).getString(KEY_REGISTRATION, null) ?: return null
        return try {
            JSONObject(raw)
        } catch (_: Exception) {
            null
        }
    }

    private fun savePermissionState(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_NOTIFICATION_ACCESS_ENABLED, enabled)
            .putString(KEY_PERMISSION_UPDATED_AT, isoNow())
            .apply()
    }

    private fun accessToJson(access: AccessDecision): JSONObject {
        return JSONObject()
            .put("allowed", access.allowed)
            .put("reason", access.reason)
            .put("role", access.role)
            .put("plan", access.plan)
            .put("action", access.action)
    }

    private fun getAllowedRoles(): Set<String> {
        val env = System.getenv("WILLIAM_ANDROID_NOTIFICATION_ALLOWED_ROLES")
        return csvToSet(env).ifEmpty {
            setOf("owner", "admin", "manager", "device_admin", "system_operator", "developer")
        }
    }

    private fun getAllowedPlans(): Set<String> {
        val env = System.getenv("WILLIAM_ANDROID_NOTIFICATION_ALLOWED_PLANS")
        return csvToSet(env).ifEmpty {
            setOf("pro", "business", "enterprise", "agency", "developer", "internal")
        }
    }

    private fun csvToSet(raw: String?): Set<String> {
        if (raw.isNullOrBlank()) return emptySet()
        return raw.split(",")
            .map { it.safeTrim(80).lowercase(Locale.US) }
            .filter { it.isNotBlank() }
            .toSet()
    }

    private fun sanitizeJson(input: JSONObject): JSONObject {
        val output = JSONObject()
        val keys = input.keys()

        while (keys.hasNext()) {
            val key = keys.next()
            val value = input.opt(key)
            val lowered = key.lowercase(Locale.US)

            if (SENSITIVE_KEYS.any { lowered.contains(it) }) {
                output.put(key, "[REDACTED]")
            } else {
                output.put(key, sanitizeValue(value))
            }
        }

        return output
    }

    private fun sanitizeValue(value: Any?): Any? {
        return when (value) {
            null -> JSONObject.NULL
            is JSONObject -> sanitizeJson(value)
            is JSONArray -> {
                val array = JSONArray()
                for (index in 0 until value.length()) {
                    array.put(sanitizeValue(value.opt(index)))
                }
                array
            }
            is String -> value.safeTrim(5000)
            is Number -> value
            is Boolean -> value
            else -> value.toString().safeTrim(1000)
        }
    }

    private fun redactIfPresent(value: String?): String? {
        return if (value.isNullOrBlank()) null else "[REDACTED]"
    }

    private fun emitReport(context: Context, report: JSONObject) {
        val safeReport = sanitizeJson(report)

        val intent = Intent(ACTION_NOTIFICATION_REPORT).apply {
            setPackage(context.packageName)
            putExtra(EXTRA_REPORT_JSON, safeReport.toString())
            putExtra(EXTRA_ACTION, safeReport.optString("action"))
            putExtra(EXTRA_STATUS, safeReport.optString("status"))
            putExtra(EXTRA_RESULT_HASH, safeReport.optString("result_hash"))
        }

        context.sendBroadcast(intent)
    }

    companion object {
        const val ACTION_NOTIFICATION_REPORT: String =
            "com.digitalpromotix.william.worker.android.NOTIFICATION_REPORT"

        const val EXTRA_REPORT_JSON: String = "report_json"
        const val EXTRA_ACTION: String = "action"
        const val EXTRA_STATUS: String = "status"
        const val EXTRA_RESULT_HASH: String = "result_hash"

        private const val PREFS_NAME = "william_notification_bridge"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_WORKER_ID = "worker_id"
        private const val KEY_REGISTRATION = "registration"
        private const val KEY_WORKER_STATE = "worker_state"
        private const val KEY_RECENT_EVENTS = "recent_events"
        private const val KEY_LAST_HEARTBEAT_AT = "last_heartbeat_at"
        private const val KEY_NOTIFICATION_ACCESS_ENABLED = "notification_access_enabled"
        private const val KEY_PERMISSION_UPDATED_AT = "permission_updated_at"

        private const val KEY_ALLOW_SENSITIVE_CONTENT = "allow_sensitive_content"
        private const val KEY_ALLOW_PACKAGES = "allow_packages"
        private const val KEY_BLOCK_PACKAGES = "block_packages"
        private const val KEY_MAX_RECENT_EVENTS = "max_recent_events"

        private const val DEFAULT_MAX_RECENT_EVENTS = 100

        private val DEFAULT_BLOCK_PACKAGES: Set<String> = setOf(
            "android",
            "com.android.systemui"
        )

        private val SENSITIVE_KEYS: Set<String> = setOf(
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "session",
            "private_key",
            "access_token",
            "refresh_token"
        )

        fun isNotificationAccessEnabled(context: Context): Boolean {
            val flat = Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            ) ?: return false

            val component = ComponentName(context, Notificationbridge::class.java)
            return flat.split(":").any {
                val enabledComponent = ComponentName.unflattenFromString(it)
                enabledComponent == component
            }
        }

        fun openNotificationAccessSettings(context: Context) {
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        }

        fun buildPermissionStatus(context: Context): JSONObject {
            return JSONObject()
                .put("notification_access_enabled", isNotificationAccessEnabled(context))
                .put("service_class", Notificationbridge::class.java.name)
                .put("package_name", context.packageName)
                .put("checked_at", isoNow())
        }

        fun saveWorkerState(context: Context, state: WorkerState) {
            prefs(context).edit()
                .putString(KEY_WORKER_STATE, state.value)
                .apply()
        }

        fun getWorkerState(context: Context): WorkerState {
            val raw = prefs(context).getString(KEY_WORKER_STATE, WorkerState.READY.value)
            return WorkerState.values().firstOrNull { it.value == raw } ?: WorkerState.READY
        }

        fun getOrCreateDeviceId(context: Context): String {
            val existing = prefs(context).getString(KEY_DEVICE_ID, null)
            if (!existing.isNullOrBlank()) return existing

            val generated = generateId("android_device")
            prefs(context).edit().putString(KEY_DEVICE_ID, generated).apply()
            return generated
        }

        fun getOrCreateWorkerId(context: Context): String {
            val existing = prefs(context).getString(KEY_WORKER_ID, null)
            if (!existing.isNullOrBlank()) return existing

            val generated = generateId("notification_worker")
            prefs(context).edit().putString(KEY_WORKER_ID, generated).apply()
            return generated
        }

        fun clearLocalBridgeState(context: Context, preserveDeviceId: Boolean = true) {
            val deviceId = prefs(context).getString(KEY_DEVICE_ID, null)
            val workerId = prefs(context).getString(KEY_WORKER_ID, null)

            prefs(context).edit().clear().apply()

            if (preserveDeviceId) {
                prefs(context).edit()
                    .putString(KEY_DEVICE_ID, deviceId ?: generateId("android_device"))
                    .putString(KEY_WORKER_ID, workerId ?: generateId("notification_worker"))
                    .apply()
            }
        }

        private fun prefs(context: Context) =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        fun isoNow(): String {
            val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            formatter.timeZone = TimeZone.getTimeZone("UTC")
            return formatter.format(Date())
        }

        fun generateId(prefix: String): String {
            return "${prefix}_${UUID.randomUUID().toString().replace("-", "")}"
        }

        fun sha256(value: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val bytes = digest.digest(value.toByteArray(Charsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        private fun jsonArrayToStringSet(array: JSONArray?): Set<String> {
            if (array == null) return emptySet()
            val output = mutableSetOf<String>()
            for (index in 0 until array.length()) {
                val item = array.optString(index).safeTrim(200)
                if (item.isNotBlank()) output.add(item)
            }
            return output
        }

        private fun String?.safeTrimOrNull(maxLength: Int): String? {
            val cleaned = this.safeTrim(maxLength)
            return cleaned.ifBlank { null }
        }

        private fun String?.safeTrim(maxLength: Int): String {
            if (this == null) return ""
            val normalized = this.trim().replace(Regex("\\s+"), " ")
            return if (normalized.length <= maxLength) normalized else normalized.substring(0, maxLength)
        }
    }
}

private fun String?.safeTrimOrNull(maxLength: Int): String? {
    val cleaned = this.safeTrim(maxLength)
    return cleaned.ifBlank { null }
}

private fun String?.safeTrim(maxLength: Int): String {
    if (this == null) return ""
    val normalized = this.trim().replace(Regex("\\s+"), " ")
    return if (normalized.length <= maxLength) normalized else normalized.substring(0, maxLength)
}
