package apps.worker_nodes.android

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.provider.Settings
import android.text.TextUtils
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Accessibilityworker
 *
 * Android AccessibilityService automation bridge for the William / Jarvis worker node.
 *
 * Core responsibilities:
 * - Register this Android worker device with the backend.
 * - Send heartbeat/status updates.
 * - Poll approved device automation tasks.
 * - Enforce user_id and workspace_id isolation.
 * - Require Security Agent approval for sensitive actions.
 * - Execute safe AccessibilityService actions.
 * - Produce audit-safe action reports.
 * - Produce Verification Agent compatible payloads.
 * - Preserve Memory Agent compatible context without leaking cross-user/workspace data.
 *
 * Important:
 * - This service does not hardcode secrets.
 * - Backend URL, worker token, user_id, workspace_id, and pause state are read from
 *   app SharedPreferences or manifest metadata.
 * - The service is designed to import safely without requiring future project files.
 */
class Accessibilityworker : AccessibilityService() {

    private val serviceRunning = AtomicBoolean(false)
    private val pollingActive = AtomicBoolean(false)
    private val lastHeartbeatAt = AtomicLong(0L)

    private lateinit var prefs: SharedPreferences
    private lateinit var workerThread: HandlerThread
    private lateinit var workerHandler: Handler

    private var lastEventPackage: String = ""
    private var lastEventClass: String = ""
    private var lastEventText: String = ""

    private val commandReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val action = intent?.action.orEmpty()
            when (action) {
                ACTION_PAUSE_WORKER -> {
                    setPaused(true)
                    auditLocal(
                        eventType = "worker_paused",
                        message = "Accessibility worker paused by local broadcast.",
                        severity = "info"
                    )
                }

                ACTION_RESUME_WORKER -> {
                    setPaused(false)
                    auditLocal(
                        eventType = "worker_resumed",
                        message = "Accessibility worker resumed by local broadcast.",
                        severity = "info"
                    )
                    startPollingLoop()
                }

                ACTION_FORCE_HEARTBEAT -> {
                    workerHandler.post { sendHeartbeat(status = "forced") }
                }

                ACTION_STOP_CURRENT_TASK -> {
                    prefs.edit().putBoolean(KEY_STOP_REQUESTED, true).apply()
                    auditLocal(
                        eventType = "task_stop_requested",
                        message = "Stop request received for current accessibility task.",
                        severity = "warning"
                    )
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        ensureDeviceId()

        workerThread = HandlerThread("WilliamAccessibilityWorker")
        workerThread.start()
        workerHandler = Handler(workerThread.looper)

        registerCommandReceiverSafely()

        serviceRunning.set(true)

        workerHandler.post {
            registerDevice()
            sendHeartbeat(status = "created")
        }
    }

    override fun onServiceConnected() {
        super.onServiceConnected()

        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                AccessibilityEvent.TYPE_VIEW_CLICKED or
                AccessibilityEvent.TYPE_VIEW_FOCUSED or
                AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED

            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            notificationTimeout = 150
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                flags = flags or AccessibilityServiceInfo.FLAG_ENABLE_ACCESSIBILITY_VOLUME
            }
        }

        serviceInfo = info

        auditLocal(
            eventType = "accessibility_service_connected",
            message = "Accessibility automation bridge connected.",
            severity = "info"
        )

        workerHandler.post {
            sendHeartbeat(status = "connected")
            startPollingLoop()
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        lastEventPackage = event.packageName?.toString().orEmpty()
        lastEventClass = event.className?.toString().orEmpty()
        lastEventText = event.text?.joinToString(separator = " ")?.take(MAX_EVENT_TEXT_LENGTH).orEmpty()

        if (shouldSendHeartbeat()) {
            workerHandler.post { sendHeartbeat(status = "active") }
        }
    }

    override fun onInterrupt() {
        auditLocal(
            eventType = "accessibility_service_interrupted",
            message = "Accessibility service interrupted by Android system.",
            severity = "warning"
        )
    }

    override fun onDestroy() {
        serviceRunning.set(false)
        pollingActive.set(false)

        try {
            unregisterReceiver(commandReceiver)
        } catch (_: Exception) {
            // Receiver may not be registered on some Android lifecycle paths.
        }

        workerHandler.post {
            sendHeartbeat(status = "destroyed")
        }

        workerThread.quitSafely()

        auditLocal(
            eventType = "accessibility_service_destroyed",
            message = "Accessibility automation bridge destroyed.",
            severity = "info"
        )

        super.onDestroy()
    }

    private fun startPollingLoop() {
        if (!serviceRunning.get()) return
        if (pollingActive.getAndSet(true)) return

        workerHandler.post(object : Runnable {
            override fun run() {
                if (!serviceRunning.get()) {
                    pollingActive.set(false)
                    return
                }

                try {
                    if (!isPaused()) {
                        pollAndExecuteTask()
                    }
                } catch (error: Exception) {
                    auditLocal(
                        eventType = "polling_error",
                        message = safeMessage(error),
                        severity = "error"
                    )
                }

                workerHandler.postDelayed(this, getPollingIntervalMs())
            }
        })
    }

    private fun pollAndExecuteTask() {
        val config = readWorkerConfig()
        if (!config.isConfigured()) {
            sendLocalOnlyHeartbeat("missing_configuration")
            return
        }

        val url = buildUrl(
            baseUrl = config.backendBaseUrl,
            path = "/api/device-workers/android/tasks",
            query = mapOf(
                "device_id" to config.deviceId,
                "user_id" to config.userId,
                "workspace_id" to config.workspaceId,
                "worker_type" to "android_accessibility"
            )
        )

        val response = httpRequest(
            method = "GET",
            url = url,
            token = config.workerToken,
            body = null
        )

        if (!response.ok) {
            auditLocal(
                eventType = "task_poll_failed",
                message = "Task polling failed with HTTP ${response.statusCode}.",
                severity = "warning"
            )
            return
        }

        val payload = parseJsonObject(response.body)
        val tasks = payload.optJSONArray("tasks") ?: JSONArray()

        if (tasks.length() == 0) {
            return
        }

        for (index in 0 until tasks.length()) {
            if (isStopRequested()) {
                clearStopRequested()
                break
            }

            val taskJson = tasks.optJSONObject(index) ?: continue
            val task = WorkerTask.fromJson(taskJson)

            val result = executeWorkerTask(task, config)
            reportTaskResult(config, task, result)
        }
    }

    private fun executeWorkerTask(task: WorkerTask, config: WorkerConfig): ActionResult {
        val startedAt = nowIso()

        if (!task.hasRequiredIdentity()) {
            return ActionResult.denied(
                code = "missing_identity",
                message = "Task denied because user_id or workspace_id is missing.",
                startedAt = startedAt
            )
        }

        if (task.userId != config.userId || task.workspaceId != config.workspaceId) {
            auditLocal(
                eventType = "workspace_isolation_block",
                message = "Blocked task ${task.taskId} due to user/workspace mismatch.",
                severity = "critical"
            )

            return ActionResult.denied(
                code = "workspace_isolation_block",
                message = "Task belongs to a different user or workspace.",
                startedAt = startedAt
            )
        }

        if (!task.isAllowedForAndroidAccessibility()) {
            return ActionResult.denied(
                code = "unsupported_action",
                message = "Action '${task.action}' is not supported by Android Accessibility worker.",
                startedAt = startedAt
            )
        }

        if (task.isSensitive() && !task.hasSecurityApproval()) {
            auditLocal(
                eventType = "security_approval_required",
                message = "Sensitive task ${task.taskId} denied because Security Agent approval is missing.",
                severity = "critical"
            )

            return ActionResult.denied(
                code = "security_approval_required",
                message = "Sensitive accessibility action requires Security Agent approval.",
                startedAt = startedAt
            )
        }

        if (!hasAccessibilityPermission()) {
            return ActionResult.denied(
                code = "accessibility_permission_missing",
                message = "Android Accessibility permission is not enabled for this service.",
                startedAt = startedAt
            )
        }

        auditLocal(
            eventType = "task_execution_started",
            message = "Executing accessibility task ${task.taskId} action=${task.action}.",
            severity = "info"
        )

        return try {
            when (task.action.lowercase(Locale.US)) {
                ACTION_GLOBAL_BACK -> performGlobalActionResult(
                    task = task,
                    globalAction = GLOBAL_ACTION_BACK,
                    startedAt = startedAt
                )

                ACTION_GLOBAL_HOME -> performGlobalActionResult(
                    task = task,
                    globalAction = GLOBAL_ACTION_HOME,
                    startedAt = startedAt
                )

                ACTION_GLOBAL_RECENTS -> performGlobalActionResult(
                    task = task,
                    globalAction = GLOBAL_ACTION_RECENTS,
                    startedAt = startedAt
                )

                ACTION_OPEN_NOTIFICATIONS -> performGlobalActionResult(
                    task = task,
                    globalAction = GLOBAL_ACTION_NOTIFICATIONS,
                    startedAt = startedAt
                )

                ACTION_OPEN_QUICK_SETTINGS -> performGlobalActionResult(
                    task = task,
                    globalAction = GLOBAL_ACTION_QUICK_SETTINGS,
                    startedAt = startedAt
                )

                ACTION_TAP_BY_TEXT -> tapByText(task, startedAt)

                ACTION_TAP_BY_VIEW_ID -> tapByViewId(task, startedAt)

                ACTION_TYPE_TEXT -> typeText(task, startedAt)

                ACTION_SCROLL_FORWARD -> scrollFocusedWindow(task, AccessibilityNodeInfo.ACTION_SCROLL_FORWARD, startedAt)

                ACTION_SCROLL_BACKWARD -> scrollFocusedWindow(task, AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD, startedAt)

                ACTION_FIND_TEXT -> findText(task, startedAt)

                ACTION_CAPTURE_SCREEN_CONTEXT -> captureScreenContext(task, startedAt)

                else -> ActionResult.denied(
                    code = "unsupported_action",
                    message = "Unsupported action '${task.action}'.",
                    startedAt = startedAt
                )
            }
        } catch (error: Exception) {
            ActionResult.failed(
                code = "execution_exception",
                message = safeMessage(error),
                startedAt = startedAt
            )
        }
    }

    private fun performGlobalActionResult(
        task: WorkerTask,
        globalAction: Int,
        startedAt: String
    ): ActionResult {
        val ok = performGlobalAction(globalAction)

        return if (ok) {
            ActionResult.success(
                code = "global_action_completed",
                message = "Global accessibility action '${task.action}' completed.",
                startedAt = startedAt,
                data = JSONObject()
                    .put("action", task.action)
                    .put("package", lastEventPackage)
            )
        } else {
            ActionResult.failed(
                code = "global_action_failed",
                message = "Android rejected global accessibility action '${task.action}'.",
                startedAt = startedAt
            )
        }
    }

    private fun tapByText(task: WorkerTask, startedAt: String): ActionResult {
        val text = task.params.optString("text", "").trim()
        if (text.isEmpty()) {
            return ActionResult.denied(
                code = "missing_text",
                message = "tap_by_text requires params.text.",
                startedAt = startedAt
            )
        }

        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val nodes = root.findAccessibilityNodeInfosByText(text)
        val clickableNode = nodes.firstOrNull { node ->
            node != null && node.isVisibleToUser && (node.isClickable || findClickableParent(node) != null)
        }

        if (clickableNode == null) {
            return ActionResult.failed(
                code = "text_not_found",
                message = "No visible clickable node found for requested text.",
                startedAt = startedAt
            )
        }

        val target = if (clickableNode.isClickable) clickableNode else findClickableParent(clickableNode)
        val clicked = target?.performAction(AccessibilityNodeInfo.ACTION_CLICK) ?: false

        recycleNodes(nodes, root)

        return if (clicked) {
            ActionResult.success(
                code = "tap_completed",
                message = "Tapped visible node matching requested text.",
                startedAt = startedAt,
                data = JSONObject()
                    .put("matched_text_hash", sha256(text))
                    .put("package", lastEventPackage)
            )
        } else {
            ActionResult.failed(
                code = "tap_failed",
                message = "Node was found but Android rejected click action.",
                startedAt = startedAt
            )
        }
    }

    private fun tapByViewId(task: WorkerTask, startedAt: String): ActionResult {
        val viewId = task.params.optString("view_id", "").trim()
        if (viewId.isEmpty()) {
            return ActionResult.denied(
                code = "missing_view_id",
                message = "tap_by_view_id requires params.view_id.",
                startedAt = startedAt
            )
        }

        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val nodes = try {
            root.findAccessibilityNodeInfosByViewId(viewId)
        } catch (error: Exception) {
            emptyList()
        }

        val clickableNode = nodes.firstOrNull { node ->
            node != null && node.isVisibleToUser && (node.isClickable || findClickableParent(node) != null)
        }

        if (clickableNode == null) {
            recycleNodes(nodes, root)
            return ActionResult.failed(
                code = "view_id_not_found",
                message = "No visible clickable node found for requested view_id.",
                startedAt = startedAt
            )
        }

        val target = if (clickableNode.isClickable) clickableNode else findClickableParent(clickableNode)
        val clicked = target?.performAction(AccessibilityNodeInfo.ACTION_CLICK) ?: false

        recycleNodes(nodes, root)

        return if (clicked) {
            ActionResult.success(
                code = "tap_completed",
                message = "Tapped visible node matching requested view_id.",
                startedAt = startedAt,
                data = JSONObject()
                    .put("view_id_hash", sha256(viewId))
                    .put("package", lastEventPackage)
            )
        } else {
            ActionResult.failed(
                code = "tap_failed",
                message = "Node was found but Android rejected click action.",
                startedAt = startedAt
            )
        }
    }

    private fun typeText(task: WorkerTask, startedAt: String): ActionResult {
        val text = task.params.optString("text", "")
        val targetText = task.params.optString("target_text", "").trim()
        val targetViewId = task.params.optString("target_view_id", "").trim()
        val replaceExisting = task.params.optBoolean("replace_existing", true)

        if (text.isEmpty()) {
            return ActionResult.denied(
                code = "missing_input_text",
                message = "type_text requires params.text.",
                startedAt = startedAt
            )
        }

        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val targetNode = when {
            targetViewId.isNotEmpty() -> {
                try {
                    root.findAccessibilityNodeInfosByViewId(targetViewId)
                        .firstOrNull { it != null && it.isVisibleToUser && it.isEditable }
                } catch (_: Exception) {
                    null
                }
            }

            targetText.isNotEmpty() -> {
                root.findAccessibilityNodeInfosByText(targetText)
                    .firstOrNull { it != null && it.isVisibleToUser && it.isEditable }
            }

            else -> {
                findFocusedEditable(root)
            }
        }

        if (targetNode == null) {
            root.recycle()
            return ActionResult.failed(
                code = "editable_field_not_found",
                message = "No editable field found for type_text.",
                startedAt = startedAt
            )
        }

        targetNode.performAction(AccessibilityNodeInfo.ACTION_FOCUS)

        if (replaceExisting && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            val clearArgs = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "")
            }
            targetNode.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, clearArgs)
        }

        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }

        val typed = targetNode.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)

        targetNode.recycle()
        root.recycle()

        return if (typed) {
            ActionResult.success(
                code = "text_input_completed",
                message = "Text entered into editable field.",
                startedAt = startedAt,
                data = JSONObject()
                    .put("input_length", text.length)
                    .put("input_hash", sha256(text))
                    .put("package", lastEventPackage)
            )
        } else {
            ActionResult.failed(
                code = "text_input_failed",
                message = "Android rejected text input action.",
                startedAt = startedAt
            )
        }
    }

    private fun scrollFocusedWindow(
        task: WorkerTask,
        scrollAction: Int,
        startedAt: String
    ): ActionResult {
        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val scrollableNode = findScrollableNode(root)
        if (scrollableNode == null) {
            root.recycle()
            return ActionResult.failed(
                code = "scrollable_node_not_found",
                message = "No scrollable node found in the active window.",
                startedAt = startedAt
            )
        }

        val scrolled = scrollableNode.performAction(scrollAction)

        scrollableNode.recycle()
        root.recycle()

        return if (scrolled) {
            ActionResult.success(
                code = "scroll_completed",
                message = "Scroll action '${task.action}' completed.",
                startedAt = startedAt,
                data = JSONObject().put("package", lastEventPackage)
            )
        } else {
            ActionResult.failed(
                code = "scroll_failed",
                message = "Android rejected scroll action.",
                startedAt = startedAt
            )
        }
    }

    private fun findText(task: WorkerTask, startedAt: String): ActionResult {
        val text = task.params.optString("text", "").trim()
        if (text.isEmpty()) {
            return ActionResult.denied(
                code = "missing_text",
                message = "find_text requires params.text.",
                startedAt = startedAt
            )
        }

        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val nodes = root.findAccessibilityNodeInfosByText(text)
        val visibleCount = nodes.count { it != null && it.isVisibleToUser }

        recycleNodes(nodes, root)

        return ActionResult.success(
            code = "text_search_completed",
            message = "Screen text search completed.",
            startedAt = startedAt,
            data = JSONObject()
                .put("found", visibleCount > 0)
                .put("visible_count", visibleCount)
                .put("query_hash", sha256(text))
                .put("package", lastEventPackage)
        )
    }

    private fun captureScreenContext(task: WorkerTask, startedAt: String): ActionResult {
        if (!task.hasSecurityApproval()) {
            return ActionResult.denied(
                code = "security_approval_required",
                message = "capture_screen_context requires Security Agent approval.",
                startedAt = startedAt
            )
        }

        val root = rootInActiveWindow ?: return ActionResult.failed(
            code = "no_active_window",
            message = "No active accessibility window is available.",
            startedAt = startedAt
        )

        val maxNodes = task.params.optInt("max_nodes", 40).coerceIn(1, 100)
        val includeText = task.params.optBoolean("include_text", false)
        val nodes = JSONArray()

        collectSafeNodeContext(
            node = root,
            output = nodes,
            maxNodes = maxNodes,
            includeText = includeText
        )

        root.recycle()

        return ActionResult.success(
            code = "screen_context_captured",
            message = "Safe screen context captured for approved task.",
            startedAt = startedAt,
            data = JSONObject()
                .put("package", lastEventPackage)
                .put("class_name", lastEventClass)
                .put("nodes", nodes)
                .put("text_redaction", if (includeText) "text_hashed" else "text_omitted")
        )
    }

    private fun collectSafeNodeContext(
        node: AccessibilityNodeInfo?,
        output: JSONArray,
        maxNodes: Int,
        includeText: Boolean
    ) {
        if (node == null || output.length() >= maxNodes) return

        val item = JSONObject()
            .put("class_name", node.className?.toString().orEmpty())
            .put("view_id_hash", node.viewIdResourceName?.let { sha256(it) } ?: "")
            .put("clickable", node.isClickable)
            .put("editable", node.isEditable)
            .put("scrollable", node.isScrollable)
            .put("visible", node.isVisibleToUser)

        if (includeText) {
            val rawText = node.text?.toString().orEmpty().take(MAX_NODE_TEXT_LENGTH)
            val rawDescription = node.contentDescription?.toString().orEmpty().take(MAX_NODE_TEXT_LENGTH)
            item.put("text_hash", if (rawText.isNotEmpty()) sha256(rawText) else "")
            item.put("description_hash", if (rawDescription.isNotEmpty()) sha256(rawDescription) else "")
            item.put("text_length", rawText.length)
            item.put("description_length", rawDescription.length)
        }

        output.put(item)

        for (i in 0 until node.childCount) {
            collectSafeNodeContext(node.getChild(i), output, maxNodes, includeText)
            if (output.length() >= maxNodes) break
        }
    }

    private fun reportTaskResult(
        config: WorkerConfig,
        task: WorkerTask,
        result: ActionResult
    ) {
        val report = JSONObject()
            .put("task_id", task.taskId)
            .put("user_id", task.userId)
            .put("workspace_id", task.workspaceId)
            .put("device_id", config.deviceId)
            .put("worker_type", "android_accessibility")
            .put("action", task.action)
            .put("status", result.status)
            .put("code", result.code)
            .put("message", result.message)
            .put("started_at", result.startedAt)
            .put("finished_at", result.finishedAt)
            .put("security_approval_id", task.securityApprovalId)
            .put("audit", buildAuditPayload(task, result))
            .put("verification", buildVerificationPayload(task, result))
            .put("memory_context", buildMemoryContextPayload(task, result))
            .put("data", result.data)

        val url = buildUrl(
            baseUrl = config.backendBaseUrl,
            path = "/api/device-workers/android/tasks/${encodePath(task.taskId)}/report",
            query = emptyMap()
        )

        val response = httpRequest(
            method = "POST",
            url = url,
            token = config.workerToken,
            body = report
        )

        if (!response.ok) {
            auditLocal(
                eventType = "task_report_failed",
                message = "Failed to report task ${task.taskId}; HTTP ${response.statusCode}.",
                severity = "warning"
            )
        }
    }

    private fun registerDevice() {
        val config = readWorkerConfig()
        if (!config.isConfigured()) {
            sendLocalOnlyHeartbeat("missing_configuration")
            return
        }

        val body = JSONObject()
            .put("device_id", config.deviceId)
            .put("worker_type", "android_accessibility")
            .put("platform", "android")
            .put("sdk_int", Build.VERSION.SDK_INT)
            .put("manufacturer", Build.MANUFACTURER)
            .put("model", Build.MODEL)
            .put("user_id", config.userId)
            .put("workspace_id", config.workspaceId)
            .put("accessibility_enabled", hasAccessibilityPermission())
            .put("paused", isPaused())
            .put("registered_at", nowIso())

        val url = buildUrl(
            baseUrl = config.backendBaseUrl,
            path = "/api/device-workers/register",
            query = emptyMap()
        )

        val response = httpRequest(
            method = "POST",
            url = url,
            token = config.workerToken,
            body = body
        )

        auditLocal(
            eventType = if (response.ok) "device_registered" else "device_registration_failed",
            message = if (response.ok) {
                "Android accessibility worker registered."
            } else {
                "Android accessibility worker registration failed with HTTP ${response.statusCode}."
            },
            severity = if (response.ok) "info" else "warning"
        )
    }

    private fun sendHeartbeat(status: String) {
        val config = readWorkerConfig()
        lastHeartbeatAt.set(System.currentTimeMillis())

        if (!config.isConfigured()) {
            sendLocalOnlyHeartbeat("missing_configuration")
            return
        }

        val body = JSONObject()
            .put("device_id", config.deviceId)
            .put("worker_type", "android_accessibility")
            .put("status", status)
            .put("service_running", serviceRunning.get())
            .put("polling_active", pollingActive.get())
            .put("paused", isPaused())
            .put("accessibility_enabled", hasAccessibilityPermission())
            .put("user_id", config.userId)
            .put("workspace_id", config.workspaceId)
            .put("last_event_package", lastEventPackage)
            .put("last_event_class", lastEventClass)
            .put("last_event_text_hash", if (lastEventText.isNotEmpty()) sha256(lastEventText) else "")
            .put("timestamp", nowIso())

        val url = buildUrl(
            baseUrl = config.backendBaseUrl,
            path = "/api/device-workers/heartbeat",
            query = emptyMap()
        )

        val response = httpRequest(
            method = "POST",
            url = url,
            token = config.workerToken,
            body = body
        )

        if (!response.ok) {
            auditLocal(
                eventType = "heartbeat_failed",
                message = "Heartbeat failed with HTTP ${response.statusCode}.",
                severity = "warning"
            )
        }
    }

    private fun sendLocalOnlyHeartbeat(reason: String) {
        lastHeartbeatAt.set(System.currentTimeMillis())
        auditLocal(
            eventType = "local_heartbeat",
            message = "Heartbeat kept local because $reason.",
            severity = "info"
        )
    }

    private fun buildAuditPayload(task: WorkerTask, result: ActionResult): JSONObject {
        return JSONObject()
            .put("event_type", "android_accessibility_task")
            .put("task_id", task.taskId)
            .put("user_id", task.userId)
            .put("workspace_id", task.workspaceId)
            .put("action", task.action)
            .put("sensitive", task.isSensitive())
            .put("security_approved", task.hasSecurityApproval())
            .put("security_approval_id", task.securityApprovalId)
            .put("status", result.status)
            .put("code", result.code)
            .put("timestamp", result.finishedAt)
            .put("package", lastEventPackage)
    }

    private fun buildVerificationPayload(task: WorkerTask, result: ActionResult): JSONObject {
        return JSONObject()
            .put("verification_type", "device_worker_action")
            .put("task_id", task.taskId)
            .put("user_id", task.userId)
            .put("workspace_id", task.workspaceId)
            .put("worker_type", "android_accessibility")
            .put("action", task.action)
            .put("expected_outcome", task.expectedOutcome)
            .put("actual_status", result.status)
            .put("actual_code", result.code)
            .put("evidence", JSONObject()
                .put("device_id_hash", sha256(readDeviceId()))
                .put("package", lastEventPackage)
                .put("finished_at", result.finishedAt)
            )
            .put("requires_human_review", result.status != STATUS_SUCCESS)
    }

    private fun buildMemoryContextPayload(task: WorkerTask, result: ActionResult): JSONObject {
        return JSONObject()
            .put("memory_scope", "workspace")
            .put("user_id", task.userId)
            .put("workspace_id", task.workspaceId)
            .put("task_id", task.taskId)
            .put("summary", "Android accessibility worker executed '${task.action}' with status '${result.status}'.")
            .put("safe_to_store", task.params.optBoolean("memory_safe", false))
            .put("contains_secret", false)
            .put("timestamp", result.finishedAt)
    }

    private fun hasAccessibilityPermission(): Boolean {
        val expectedService = "${packageName}/${javaClass.name}"
        val enabledServices = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false

        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(enabledServices)

        while (splitter.hasNext()) {
            val enabledService = splitter.next()
            if (enabledService.equals(expectedService, ignoreCase = true)) {
                return true
            }
        }

        return false
    }

    private fun findClickableParent(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        var current = node?.parent
        while (current != null) {
            if (current.isClickable && current.isVisibleToUser) {
                return current
            }
            current = current.parent
        }
        return null
    }

    private fun findScrollableNode(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) return null
        if (node.isScrollable && node.isVisibleToUser) return node

        for (i in 0 until node.childCount) {
            val child = node.getChild(i)
            val result = findScrollableNode(child)
            if (result != null) return result
            child?.recycle()
        }

        return null
    }

    private fun findFocusedEditable(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (focused != null && focused.isEditable && focused.isVisibleToUser) {
            return focused
        }

        return findFirstEditable(root)
    }

    private fun findFirstEditable(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) return null
        if (node.isEditable && node.isVisibleToUser) return node

        for (i in 0 until node.childCount) {
            val child = node.getChild(i)
            val result = findFirstEditable(child)
            if (result != null) return result
            child?.recycle()
        }

        return null
    }

    private fun recycleNodes(nodes: List<AccessibilityNodeInfo?>, root: AccessibilityNodeInfo?) {
        for (node in nodes) {
            try {
                node?.recycle()
            } catch (_: Exception) {
                // Ignore recycle errors from Android framework edge cases.
            }
        }

        try {
            root?.recycle()
        } catch (_: Exception) {
            // Ignore recycle errors from Android framework edge cases.
        }
    }

    private fun readWorkerConfig(): WorkerConfig {
        return WorkerConfig(
            backendBaseUrl = readStringConfig(KEY_BACKEND_BASE_URL, META_BACKEND_BASE_URL).trimEnd('/'),
            workerToken = readStringConfig(KEY_WORKER_TOKEN, META_WORKER_TOKEN),
            deviceId = readDeviceId(),
            userId = readStringConfig(KEY_USER_ID, META_USER_ID),
            workspaceId = readStringConfig(KEY_WORKSPACE_ID, META_WORKSPACE_ID)
        )
    }

    private fun readStringConfig(prefKey: String, metaKey: String): String {
        val fromPrefs = prefs.getString(prefKey, "").orEmpty()
        if (fromPrefs.isNotBlank()) return fromPrefs

        return try {
            val appInfo: ApplicationInfo = packageManager.getApplicationInfo(
                packageName,
                PackageManagerFlags.metaDataFlag()
            )
            appInfo.metaData?.getString(metaKey).orEmpty()
        } catch (_: Exception) {
            ""
        }
    }

    private fun ensureDeviceId() {
        val existing = prefs.getString(KEY_DEVICE_ID, "").orEmpty()
        if (existing.isNotBlank()) return

        val androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
            ?: UUID.randomUUID().toString()

        val generated = "android-${sha256("$packageName:$androidId").take(24)}"
        prefs.edit().putString(KEY_DEVICE_ID, generated).apply()
    }

    private fun readDeviceId(): String {
        ensureDeviceId()
        return prefs.getString(KEY_DEVICE_ID, "").orEmpty()
    }

    private fun isPaused(): Boolean {
        return prefs.getBoolean(KEY_WORKER_PAUSED, false)
    }

    private fun setPaused(paused: Boolean) {
        prefs.edit().putBoolean(KEY_WORKER_PAUSED, paused).apply()
    }

    private fun isStopRequested(): Boolean {
        return prefs.getBoolean(KEY_STOP_REQUESTED, false)
    }

    private fun clearStopRequested() {
        prefs.edit().putBoolean(KEY_STOP_REQUESTED, false).apply()
    }

    private fun getPollingIntervalMs(): Long {
        val configured = prefs.getLong(KEY_POLLING_INTERVAL_MS, DEFAULT_POLLING_INTERVAL_MS)
        return configured.coerceIn(MIN_POLLING_INTERVAL_MS, MAX_POLLING_INTERVAL_MS)
    }

    private fun shouldSendHeartbeat(): Boolean {
        return System.currentTimeMillis() - lastHeartbeatAt.get() > HEARTBEAT_INTERVAL_MS
    }

    private fun httpRequest(
        method: String,
        url: String,
        token: String,
        body: JSONObject?
    ): HttpResponse {
        var connection: HttpURLConnection? = null

        return try {
            connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = method
            connection.connectTimeout = HTTP_CONNECT_TIMEOUT_MS
            connection.readTimeout = HTTP_READ_TIMEOUT_MS
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("X-Worker-Type", "android_accessibility")

            if (token.isNotBlank()) {
                connection.setRequestProperty("Authorization", "Bearer $token")
            }

            if (body != null) {
                connection.doOutput = true
                OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                    writer.write(body.toString())
                    writer.flush()
                }
            }

            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }

            val responseBody = stream?.bufferedReader(Charsets.UTF_8)?.use(BufferedReader::readText).orEmpty()

            HttpResponse(
                ok = statusCode in 200..299,
                statusCode = statusCode,
                body = responseBody
            )
        } catch (error: Exception) {
            HttpResponse(
                ok = false,
                statusCode = -1,
                body = JSONObject()
                    .put("error", safeMessage(error))
                    .toString()
            )
        } finally {
            connection?.disconnect()
        }
    }

    private fun parseJsonObject(raw: String): JSONObject {
        return try {
            if (raw.isBlank()) JSONObject() else JSONObject(raw)
        } catch (_: Exception) {
            JSONObject()
        }
    }

    private fun buildUrl(baseUrl: String, path: String, query: Map<String, String>): String {
        val cleanBase = baseUrl.trimEnd('/')
        val cleanPath = if (path.startsWith("/")) path else "/$path"

        if (query.isEmpty()) {
            return "$cleanBase$cleanPath"
        }

        val queryString = query.entries.joinToString("&") { entry ->
            "${entry.key.urlEncode()}=${entry.value.urlEncode()}"
        }

        return "$cleanBase$cleanPath?$queryString"
    }

    private fun encodePath(value: String): String {
        return value.urlEncode().replace("+", "%20")
    }

    private fun String.urlEncode(): String {
        return java.net.URLEncoder.encode(this, "UTF-8")
    }

    private fun auditLocal(eventType: String, message: String, severity: String) {
        val payload = JSONObject()
            .put("event_type", eventType)
            .put("message", message)
            .put("severity", severity)
            .put("device_id_hash", sha256(readDeviceId()))
            .put("user_id_hash", sha256(readStringConfig(KEY_USER_ID, META_USER_ID)))
            .put("workspace_id_hash", sha256(readStringConfig(KEY_WORKSPACE_ID, META_WORKSPACE_ID)))
            .put("timestamp", nowIso())

        Log.i(LOG_TAG, payload.toString())
    }

    private fun registerCommandReceiverSafely() {
        val filter = IntentFilter().apply {
            addAction(ACTION_PAUSE_WORKER)
            addAction(ACTION_RESUME_WORKER)
            addAction(ACTION_FORCE_HEARTBEAT)
            addAction(ACTION_STOP_CURRENT_TASK)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(commandReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(commandReceiver, filter)
        }
    }

    private fun safeMessage(error: Throwable): String {
        return error.message
            ?.replace(Regex("Bearer\\s+[A-Za-z0-9._\\-]+"), "Bearer [redacted]")
            ?.take(500)
            ?: error.javaClass.simpleName
    }

    private fun sha256(value: String): String {
        if (value.isBlank()) return ""
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(value.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun nowIso(): String {
        return java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(java.util.Date())
    }

    data class WorkerConfig(
        val backendBaseUrl: String,
        val workerToken: String,
        val deviceId: String,
        val userId: String,
        val workspaceId: String
    ) {
        fun isConfigured(): Boolean {
            return backendBaseUrl.startsWith("https://") &&
                workerToken.isNotBlank() &&
                deviceId.isNotBlank() &&
                userId.isNotBlank() &&
                workspaceId.isNotBlank()
        }
    }

    data class WorkerTask(
        val taskId: String,
        val userId: String,
        val workspaceId: String,
        val action: String,
        val params: JSONObject,
        val sensitive: Boolean,
        val securityApproved: Boolean,
        val securityApprovalId: String,
        val expectedOutcome: String,
        val createdAt: String
    ) {
        fun hasRequiredIdentity(): Boolean {
            return taskId.isNotBlank() && userId.isNotBlank() && workspaceId.isNotBlank()
        }

        fun isSensitive(): Boolean {
            val normalizedAction = action.lowercase(Locale.US)

            if (sensitive) return true

            return normalizedAction in setOf(
                ACTION_TYPE_TEXT,
                ACTION_OPEN_NOTIFICATIONS,
                ACTION_OPEN_QUICK_SETTINGS,
                ACTION_CAPTURE_SCREEN_CONTEXT
            )
        }

        fun hasSecurityApproval(): Boolean {
            return securityApproved && securityApprovalId.isNotBlank()
        }

        fun isAllowedForAndroidAccessibility(): Boolean {
            return action.lowercase(Locale.US) in SUPPORTED_ACTIONS
        }

        companion object {
            fun fromJson(json: JSONObject): WorkerTask {
                return WorkerTask(
                    taskId = json.optString("task_id", json.optString("id", "")),
                    userId = json.optString("user_id", ""),
                    workspaceId = json.optString("workspace_id", ""),
                    action = json.optString("action", "").lowercase(Locale.US),
                    params = json.optJSONObject("params") ?: JSONObject(),
                    sensitive = json.optBoolean("sensitive", false),
                    securityApproved = json.optBoolean("security_approved", false),
                    securityApprovalId = json.optString("security_approval_id", ""),
                    expectedOutcome = json.optString("expected_outcome", ""),
                    createdAt = json.optString("created_at", "")
                )
            }
        }
    }

    data class ActionResult(
        val status: String,
        val code: String,
        val message: String,
        val startedAt: String,
        val finishedAt: String,
        val data: JSONObject
    ) {
        companion object {
            fun success(
                code: String,
                message: String,
                startedAt: String,
                data: JSONObject = JSONObject()
            ): ActionResult {
                return ActionResult(
                    status = STATUS_SUCCESS,
                    code = code,
                    message = message,
                    startedAt = startedAt,
                    finishedAt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
                        timeZone = java.util.TimeZone.getTimeZone("UTC")
                    }.format(java.util.Date()),
                    data = data
                )
            }

            fun failed(
                code: String,
                message: String,
                startedAt: String,
                data: JSONObject = JSONObject()
            ): ActionResult {
                return ActionResult(
                    status = STATUS_FAILED,
                    code = code,
                    message = message,
                    startedAt = startedAt,
                    finishedAt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
                        timeZone = java.util.TimeZone.getTimeZone("UTC")
                    }.format(java.util.Date()),
                    data = data
                )
            }

            fun denied(
                code: String,
                message: String,
                startedAt: String,
                data: JSONObject = JSONObject()
            ): ActionResult {
                return ActionResult(
                    status = STATUS_DENIED,
                    code = code,
                    message = message,
                    startedAt = startedAt,
                    finishedAt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
                        timeZone = java.util.TimeZone.getTimeZone("UTC")
                    }.format(java.util.Date()),
                    data = data
                )
            }
        }
    }

    data class HttpResponse(
        val ok: Boolean,
        val statusCode: Int,
        val body: String
    )

    object PackageManagerFlags {
        fun metaDataFlag(): Int {
            return android.content.pm.PackageManager.GET_META_DATA
        }
    }

    companion object {
        private const val LOG_TAG = "WilliamAccessibility"

        private const val PREFS_NAME = "william_android_worker"

        private const val KEY_BACKEND_BASE_URL = "backend_base_url"
        private const val KEY_WORKER_TOKEN = "worker_token"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_WORKSPACE_ID = "workspace_id"
        private const val KEY_WORKER_PAUSED = "worker_paused"
        private const val KEY_STOP_REQUESTED = "stop_requested"
        private const val KEY_POLLING_INTERVAL_MS = "polling_interval_ms"

        private const val META_BACKEND_BASE_URL = "william.backend_base_url"
        private const val META_WORKER_TOKEN = "william.worker_token"
        private const val META_USER_ID = "william.user_id"
        private const val META_WORKSPACE_ID = "william.workspace_id"

        private const val DEFAULT_POLLING_INTERVAL_MS = 5_000L
        private const val MIN_POLLING_INTERVAL_MS = 2_000L
        private const val MAX_POLLING_INTERVAL_MS = 60_000L
        private const val HEARTBEAT_INTERVAL_MS = 30_000L

        private const val HTTP_CONNECT_TIMEOUT_MS = 8_000
        private const val HTTP_READ_TIMEOUT_MS = 12_000

        private const val MAX_EVENT_TEXT_LENGTH = 300
        private const val MAX_NODE_TEXT_LENGTH = 120

        private const val STATUS_SUCCESS = "success"
        private const val STATUS_FAILED = "failed"
        private const val STATUS_DENIED = "denied"

        private const val ACTION_GLOBAL_BACK = "global_back"
        private const val ACTION_GLOBAL_HOME = "global_home"
        private const val ACTION_GLOBAL_RECENTS = "global_recents"
        private const val ACTION_OPEN_NOTIFICATIONS = "open_notifications"
        private const val ACTION_OPEN_QUICK_SETTINGS = "open_quick_settings"
        private const val ACTION_TAP_BY_TEXT = "tap_by_text"
        private const val ACTION_TAP_BY_VIEW_ID = "tap_by_view_id"
        private const val ACTION_TYPE_TEXT = "type_text"
        private const val ACTION_SCROLL_FORWARD = "scroll_forward"
        private const val ACTION_SCROLL_BACKWARD = "scroll_backward"
        private const val ACTION_FIND_TEXT = "find_text"
        private const val ACTION_CAPTURE_SCREEN_CONTEXT = "capture_screen_context"

        private val SUPPORTED_ACTIONS = setOf(
            ACTION_GLOBAL_BACK,
            ACTION_GLOBAL_HOME,
            ACTION_GLOBAL_RECENTS,
            ACTION_OPEN_NOTIFICATIONS,
            ACTION_OPEN_QUICK_SETTINGS,
            ACTION_TAP_BY_TEXT,
            ACTION_TAP_BY_VIEW_ID,
            ACTION_TYPE_TEXT,
            ACTION_SCROLL_FORWARD,
            ACTION_SCROLL_BACKWARD,
            ACTION_FIND_TEXT,
            ACTION_CAPTURE_SCREEN_CONTEXT
        )

        const val ACTION_PAUSE_WORKER = "com.digitalpromotix.william.worker.PAUSE_ACCESSIBILITY"
        const val ACTION_RESUME_WORKER = "com.digitalpromotix.william.worker.RESUME_ACCESSIBILITY"
        const val ACTION_FORCE_HEARTBEAT = "com.digitalpromotix.william.worker.FORCE_HEARTBEAT"
        const val ACTION_STOP_CURRENT_TASK = "com.digitalpromotix.william.worker.STOP_CURRENT_TASK"
    }
}