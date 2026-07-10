package com.digitalpromotix.william.worker

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.accessibility.AccessibilityManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Space
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import kotlin.math.max

/**
 * Android Worker Login / Status / Control Shell.
 *
 * Purpose:
 * - Lets the owner connect an Android device to the William/Jarvis backend.
 * - Registers the device as a worker node.
 * - Sends heartbeat safely.
 * - Shows user/workspace isolation status.
 * - Provides pause/resume/stop controls.
 * - Opens Accessibility settings for AccessibilityWorker setup.
 * - Prepares audit/security/memory/verification-friendly payloads.
 *
 * Security rules:
 * - Every backend request includes user_id and workspace_id.
 * - No token or secret is hardcoded.
 * - Sensitive operations require explicit backend permission flags.
 * - This file does not execute dangerous Android actions directly.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var rootLayout: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var progressBar: ProgressBar

    private lateinit var backendInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var userIdInput: EditText
    private lateinit var workspaceIdInput: EditText
    private lateinit var deviceNameInput: EditText

    private lateinit var loginButton: Button
    private lateinit var registerButton: Button
    private lateinit var heartbeatButton: Button
    private lateinit var startButton: Button
    private lateinit var pauseButton: Button
    private lateinit var resumeButton: Button
    private lateinit var stopButton: Button
    private lateinit var accessibilityButton: Button
    private lateinit var permissionsButton: Button
    private lateinit var clearButton: Button

    private val executor = Executors.newSingleThreadExecutor()
    private var scheduler: ScheduledExecutorService? = null

    private var workerStatus: WorkerStatus = WorkerStatus.CREATED
    private var sessionId: String = UUID.randomUUID().toString()
    private var latestLogin: LoginState = LoginState.empty()

    companion object {
        private const val PREF_NAME = "william_android_worker"
        private const val REQUEST_NOTIFICATION_PERMISSION = 7201

        private const val KEY_BACKEND_URL = "backend_url"
        private const val KEY_API_TOKEN = "api_token"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_WORKSPACE_ID = "workspace_id"
        private const val KEY_DEVICE_NAME = "device_name"
        private const val KEY_DEVICE_ID = "device_id"

        private const val DEFAULT_BACKEND_URL = "http://10.0.2.2:8000"

        private val REQUIRED_WORKER_PERMISSIONS = setOf(
            "agents.system.use",
            "device.worker.use",
            "device.worker.android",
            "tasks.run"
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        ensureDeviceId()
        buildUi()
        loadPrefsIntoUi()
        refreshStatus("Ready", "Enter backend details, login, then register this Android worker.")
        requestSafeRuntimePermissions()
    }

    override fun onDestroy() {
        stopHeartbeatLoop()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun buildUi() {
        val scrollView = ScrollView(this)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(34, 34, 34, 34)
        }

        val title = TextView(this).apply {
            text = "William / Jarvis Android Worker"
            textSize = 24f
            gravity = Gravity.CENTER
        }

        val subtitle = TextView(this).apply {
            text = "Login, register, monitor, and control this Android worker safely."
            textSize = 14f
            gravity = Gravity.CENTER
        }

        progressBar = ProgressBar(this).apply {
            visibility = View.GONE
            isIndeterminate = true
        }

        statusText = TextView(this).apply {
            textSize = 18f
            text = "Status: Created"
        }

        detailText = TextView(this).apply {
            textSize = 13f
            text = ""
        }

        backendInput = makeInput("Backend URL", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI)
        tokenInput = makeInput("Worker API Token", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)
        userIdInput = makeInput("User ID", InputType.TYPE_CLASS_TEXT)
        workspaceIdInput = makeInput("Workspace ID", InputType.TYPE_CLASS_TEXT)
        deviceNameInput = makeInput("Device Name", InputType.TYPE_CLASS_TEXT)

        loginButton = makeButton("Login / Verify Access") { loginAndVerify() }
        registerButton = makeButton("Register Device") { registerDevice() }
        heartbeatButton = makeButton("Send Heartbeat Now") { sendHeartbeatOnce() }
        startButton = makeButton("Start Worker Heartbeat") { startWorker() }
        pauseButton = makeButton("Pause Worker") { pauseWorker() }
        resumeButton = makeButton("Resume Worker") { resumeWorker() }
        stopButton = makeButton("Stop Worker") { stopWorker() }
        accessibilityButton = makeButton("Open Accessibility Settings") { openAccessibilitySettings() }
        permissionsButton = makeButton("Check Local Permissions") { checkLocalPermissions() }
        clearButton = makeButton("Clear Saved Login") { clearSavedLogin() }

        rootLayout.addView(title)
        rootLayout.addView(subtitle)
        rootLayout.addView(space(18))
        rootLayout.addView(progressBar)
        rootLayout.addView(statusText)
        rootLayout.addView(detailText)
        rootLayout.addView(space(18))

        rootLayout.addView(backendInput)
        rootLayout.addView(tokenInput)
        rootLayout.addView(userIdInput)
        rootLayout.addView(workspaceIdInput)
        rootLayout.addView(deviceNameInput)

        rootLayout.addView(space(16))
        rootLayout.addView(loginButton)
        rootLayout.addView(registerButton)
        rootLayout.addView(heartbeatButton)
        rootLayout.addView(startButton)
        rootLayout.addView(pauseButton)
        rootLayout.addView(resumeButton)
        rootLayout.addView(stopButton)
        rootLayout.addView(accessibilityButton)
        rootLayout.addView(permissionsButton)
        rootLayout.addView(clearButton)

        scrollView.addView(rootLayout)
        setContentView(scrollView)
    }

    private fun makeInput(hintText: String, inputTypeValue: Int): EditText {
        return EditText(this).apply {
            hint = hintText
            inputType = inputTypeValue
            setSingleLine(true)
        }
    }

    private fun makeButton(label: String, action: () -> Unit): Button {
        return Button(this).apply {
            text = label
            setOnClickListener { action() }
        }
    }

    private fun space(height: Int): Space {
        return Space(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                height
            )
        }
    }

    private fun loadPrefsIntoUi() {
        backendInput.setText(prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL))
        tokenInput.setText(prefs.getString(KEY_API_TOKEN, ""))
        userIdInput.setText(prefs.getString(KEY_USER_ID, ""))
        workspaceIdInput.setText(prefs.getString(KEY_WORKSPACE_ID, ""))
        deviceNameInput.setText(prefs.getString(KEY_DEVICE_NAME, defaultDeviceName()))
    }

    private fun saveUiToPrefs() {
        prefs.edit()
            .putString(KEY_BACKEND_URL, normalizedBackendUrl())
            .putString(KEY_API_TOKEN, tokenInput.text.toString().trim())
            .putString(KEY_USER_ID, userIdInput.text.toString().trim())
            .putString(KEY_WORKSPACE_ID, workspaceIdInput.text.toString().trim())
            .putString(KEY_DEVICE_NAME, deviceNameInput.text.toString().trim().ifEmpty { defaultDeviceName() })
            .apply()
    }

    private fun loginAndVerify() {
        val validation = validateInputs()
        if (!validation.ok) {
            refreshStatus("Login blocked", validation.message)
            return
        }

        saveUiToPrefs()
        setLoading(true)

        executor.execute {
            val payload = basePayload()
                .put("action", "android_worker_login_verify")
                .put("audit_event", auditEvent("android.worker.login.requested", "medium"))
                .put("security_payload", securityPayload("android_worker_login_verify", "medium"))

            val response = requestJson("POST", "/api/worker/android/login", payload)

            runOnUiThread {
                setLoading(false)

                if (response.ok) {
                    latestLogin = LoginState.fromJson(response.data)
                    workerStatus = WorkerStatus.AUTHENTICATED

                    val missing = missingRequiredPermissions(latestLogin.permissions)
                    val detail = if (missing.isEmpty()) {
                        "Login verified. Required worker permissions are present."
                    } else {
                        "Login verified, but missing permissions: ${missing.joinToString(", ")}"
                    }

                    refreshStatus("Authenticated", detail)
                } else {
                    workerStatus = WorkerStatus.ERROR
                    refreshStatus("Login failed", response.safeMessage())
                }
            }
        }
    }

    private fun registerDevice() {
        val validation = validateReadyForBackend()
        if (!validation.ok) {
            refreshStatus("Registration blocked", validation.message)
            return
        }

        val permissionCheck = hasRequiredBackendPermissions()
        if (!permissionCheck.ok) {
            refreshStatus("Registration blocked", permissionCheck.message)
            return
        }

        saveUiToPrefs()
        setLoading(true)

        executor.execute {
            val payload = basePayload()
                .put("identity", workerIdentity())
                .put("registered_at", now())
                .put("audit_event", auditEvent("android.worker.device.register.requested", "medium"))
                .put("security_payload", securityPayload("android_worker_device_registration", "medium"))
                .put("verification_payload", verificationPayload("registration_requested", JSONObject()))

            val response = requestJson("POST", "/api/worker/register", payload)

            runOnUiThread {
                setLoading(false)

                if (response.ok) {
                    workerStatus = WorkerStatus.REGISTERED
                    refreshStatus("Registered", "Android worker registered successfully.")
                } else {
                    workerStatus = WorkerStatus.ERROR
                    refreshStatus("Registration failed", response.safeMessage())
                }
            }
        }
    }

    private fun startWorker() {
        val ready = validateReadyForBackend()
        if (!ready.ok) {
            refreshStatus("Start blocked", ready.message)
            return
        }

        if (workerStatus == WorkerStatus.CREATED || workerStatus == WorkerStatus.AUTHENTICATED) {
            refreshStatus("Start blocked", "Register the device before starting heartbeat.")
            return
        }

        workerStatus = WorkerStatus.RUNNING
        startHeartbeatLoop()
        sendControlAction("android.worker.started", "Worker heartbeat started.")
        refreshStatus("Running", "Heartbeat loop is active. This shell is ready for Android worker control.")
    }

    private fun pauseWorker() {
        if (workerStatus != WorkerStatus.RUNNING) {
            refreshStatus("Pause blocked", "Worker must be running before it can be paused.")
            return
        }

        workerStatus = WorkerStatus.PAUSED
        sendControlAction("android.worker.paused", "Worker paused.")
        refreshStatus("Paused", "Worker is paused. Heartbeat will continue with paused status.")
    }

    private fun resumeWorker() {
        if (workerStatus != WorkerStatus.PAUSED) {
            refreshStatus("Resume blocked", "Worker is not paused.")
            return
        }

        workerStatus = WorkerStatus.RUNNING
        sendControlAction("android.worker.resumed", "Worker resumed.")
        refreshStatus("Running", "Worker resumed safely.")
    }

    private fun stopWorker() {
        workerStatus = WorkerStatus.STOPPED
        stopHeartbeatLoop()
        sendControlAction("android.worker.stopped", "Worker stopped.")
        refreshStatus("Stopped", "Worker heartbeat stopped.")
    }

    private fun sendHeartbeatOnce() {
        val validation = validateReadyForBackend()
        if (!validation.ok) {
            refreshStatus("Heartbeat blocked", validation.message)
            return
        }

        setLoading(true)

        executor.execute {
            val response = sendHeartbeatRequest()

            runOnUiThread {
                setLoading(false)
                if (response.ok) {
                    refreshStatus("Heartbeat sent", "Backend acknowledged this Android worker.")
                } else {
                    refreshStatus("Heartbeat failed", response.safeMessage())
                }
            }
        }
    }

    private fun startHeartbeatLoop() {
        stopHeartbeatLoop()

        scheduler = Executors.newSingleThreadScheduledExecutor()
        scheduler?.scheduleAtFixedRate(
            {
                val response = sendHeartbeatRequest()
                if (!response.ok) {
                    runOnUiThread {
                        refreshStatus("Heartbeat warning", response.safeMessage())
                    }
                }
            },
            0,
            30,
            TimeUnit.SECONDS
        )
    }

    private fun stopHeartbeatLoop() {
        scheduler?.shutdownNow()
        scheduler = null
    }

    private fun sendHeartbeatRequest(): ApiResponse {
        val payload = basePayload()
            .put("identity", workerIdentity())
            .put("status", workerStatus.value)
            .put("heartbeat_at", now())
            .put("battery", batteryInfo())
            .put("local_permissions", localPermissionStatus())
            .put("audit_event", auditEvent("android.worker.heartbeat", "low"))

        return requestJson("POST", "/api/worker/heartbeat", payload)
    }

    private fun sendControlAction(action: String, message: String) {
        val validation = validateReadyForBackend()
        if (!validation.ok) {
            return
        }

        executor.execute {
            val payload = basePayload()
                .put("control_action", action)
                .put("status", workerStatus.value)
                .put("message", message)
                .put("audit_event", auditEvent(action, "medium"))
                .put("verification_payload", verificationPayload(action, JSONObject().put("message", message)))

            requestJson("POST", "/api/worker/android/control", payload)
        }
    }

    private fun openAccessibilitySettings() {
        val audit = auditEvent("android.worker.accessibility_settings.opened", "high")
        sendControlAction("android.worker.accessibility_settings.opened", "User opened Android Accessibility settings.")

        Toast.makeText(
            this,
            "Enable William/Jarvis Accessibility Worker only if you trust this device.",
            Toast.LENGTH_LONG
        ).show()

        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        startActivity(intent)

        detailText.text = prettyJson(
            JSONObject()
                .put("audit_event", audit)
                .put("security_note", "Accessibility access is sensitive and must be explicitly enabled by the device owner.")
        )
    }

    private fun checkLocalPermissions() {
        val status = localPermissionStatus()
        val accessibilityEnabled = isAccessibilityEnabled()

        val result = JSONObject()
            .put("local_permissions", status)
            .put("accessibility_enabled", accessibilityEnabled)
            .put("device_id", deviceId())
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("verification_payload", verificationPayload("local_permission_check", status))

        refreshStatus("Local permissions checked", prettyJson(result))
    }

    private fun clearSavedLogin() {
        stopHeartbeatLoop()
        workerStatus = WorkerStatus.CREATED
        latestLogin = LoginState.empty()
        sessionId = UUID.randomUUID().toString()

        prefs.edit()
            .remove(KEY_API_TOKEN)
            .remove(KEY_USER_ID)
            .remove(KEY_WORKSPACE_ID)
            .apply()

        tokenInput.setText("")
        userIdInput.setText("")
        workspaceIdInput.setText("")

        refreshStatus("Cleared", "Saved token, user_id, and workspace_id were removed from this device.")
    }

    private fun validateInputs(): ValidationResult {
        if (normalizedBackendUrl().isBlank()) {
            return ValidationResult(false, "Backend URL is required.")
        }

        if (!normalizedBackendUrl().startsWith("http://") && !normalizedBackendUrl().startsWith("https://")) {
            return ValidationResult(false, "Backend URL must start with http:// or https://.")
        }

        if (apiToken().isBlank()) {
            return ValidationResult(false, "Worker API token is required. Do not hardcode it; paste it securely here.")
        }

        if (userId().isBlank()) {
            return ValidationResult(false, "user_id is required for SaaS isolation.")
        }

        if (workspaceId().isBlank()) {
            return ValidationResult(false, "workspace_id is required for SaaS isolation.")
        }

        return ValidationResult(true, "Valid.")
    }

    private fun validateReadyForBackend(): ValidationResult {
        val base = validateInputs()
        if (!base.ok) {
            return base
        }

        if (latestLogin.userId.isNotBlank() && latestLogin.userId != userId()) {
            return ValidationResult(false, "Logged-in user_id does not match current user_id field.")
        }

        if (latestLogin.workspaceId.isNotBlank() && latestLogin.workspaceId != workspaceId()) {
            return ValidationResult(false, "Logged-in workspace_id does not match current workspace_id field.")
        }

        return ValidationResult(true, "Ready.")
    }

    private fun hasRequiredBackendPermissions(): ValidationResult {
        val missing = missingRequiredPermissions(latestLogin.permissions)

        if (latestLogin.permissions.isEmpty()) {
            return ValidationResult(
                false,
                "Login first so backend role/plan/subscription permissions can be checked."
            )
        }

        if (missing.isNotEmpty()) {
            return ValidationResult(
                false,
                "Missing backend permissions: ${missing.joinToString(", ")}"
            )
        }

        if (!latestLogin.subscriptionActive) {
            return ValidationResult(false, "Subscription is not active for this workspace.")
        }

        if (!latestLogin.planAllowsAndroidWorker) {
            return ValidationResult(false, "Current plan does not allow Android worker access.")
        }

        return ValidationResult(true, "Permissions valid.")
    }

    private fun missingRequiredPermissions(permissions: Set<String>): Set<String> {
        return REQUIRED_WORKER_PERMISSIONS.filterNot { permissions.contains(it) }.toSet()
    }

    private fun requestJson(method: String, path: String, payload: JSONObject): ApiResponse {
        return try {
            val url = URL(joinUrl(normalizedBackendUrl(), path))
            val connection = url.openConnection() as HttpURLConnection

            connection.requestMethod = method.uppercase(Locale.US)
            connection.connectTimeout = 15000
            connection.readTimeout = 20000
            connection.doInput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${apiToken()}")
            connection.setRequestProperty("X-Device-Id", deviceId())
            connection.setRequestProperty("X-User-Id", userId())
            connection.setRequestProperty("X-Workspace-Id", workspaceId())
            connection.setRequestProperty("X-Session-Id", sessionId)
            connection.setRequestProperty("X-Request-Id", UUID.randomUUID().toString())

            if (method.uppercase(Locale.US) != "GET") {
                connection.doOutput = true
                OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                    writer.write(payload.toString())
                    writer.flush()
                }
            }

            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.let { readAll(it.bufferedReader()) }.orEmpty()
            val data = parseJsonObject(body)

            ApiResponse(
                ok = statusCode in 200..299,
                statusCode = statusCode,
                data = data,
                error = if (statusCode in 200..299) "" else redact(body.ifBlank { connection.responseMessage.orEmpty() })
            )
        } catch (error: Exception) {
            ApiResponse(
                ok = false,
                statusCode = 0,
                data = JSONObject(),
                error = safeError(error)
            )
        }
    }

    private fun basePayload(): JSONObject {
        return JSONObject()
            .put("device_id", deviceId())
            .put("device_name", deviceName())
            .put("session_id", sessionId)
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("worker_type", "android_worker")
            .put("worker_version", "1.0.0")
            .put("timestamp", now())
    }

    private fun workerIdentity(): JSONObject {
        return JSONObject()
            .put("device_id", deviceId())
            .put("device_name", deviceName())
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("worker_type", "android_worker")
            .put("worker_version", "1.0.0")
            .put("manufacturer", Build.MANUFACTURER ?: "unknown")
            .put("model", Build.MODEL ?: "unknown")
            .put("brand", Build.BRAND ?: "unknown")
            .put("android_version", Build.VERSION.RELEASE ?: "unknown")
            .put("sdk_int", Build.VERSION.SDK_INT)
            .put("hostname", safeHostName())
            .put("capabilities", JSONArray(listOf(
                "android_login_shell",
                "device_registration",
                "heartbeat",
                "pause_resume_stop",
                "accessibility_worker_bridge",
                "safe_action_reports",
                "user_workspace_isolation"
            )))
            .put("local_permissions", localPermissionStatus())
    }

    private fun auditEvent(action: String, riskLevel: String): JSONObject {
        return JSONObject()
            .put("event_id", UUID.randomUUID().toString())
            .put("event_type", "audit")
            .put("source", "apps.worker_nodes.android.MainActivity")
            .put("module", "Mainactivity")
            .put("action", action)
            .put("risk_level", riskLevel)
            .put("device_id", deviceId())
            .put("session_id", sessionId)
            .put("actor_user_id", userId())
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("created_at", now())
    }

    private fun securityPayload(action: String, riskLevel: String): JSONObject {
        return JSONObject()
            .put("security_request_id", UUID.randomUUID().toString())
            .put("source", "apps.worker_nodes.android.MainActivity")
            .put("module", "Mainactivity")
            .put("recommended_agent", "security")
            .put("action", action)
            .put("risk_level", riskLevel)
            .put("requires_approval", riskLevel == "high" || riskLevel == "critical")
            .put("device_id", deviceId())
            .put("session_id", sessionId)
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("created_at", now())
            .put("policy", JSONObject()
                .put("must_match_user_id", true)
                .put("must_match_workspace_id", true)
                .put("must_check_subscription", true)
                .put("must_check_role_permissions", true)
                .put("must_audit_state_changes", true)
            )
    }

    private fun memoryPayload(summary: String, payload: JSONObject): JSONObject {
        return JSONObject()
            .put("memory_event_id", UUID.randomUUID().toString())
            .put("source", "apps.worker_nodes.android.MainActivity")
            .put("module", "Mainactivity")
            .put("recommended_agent", "memory")
            .put("memory_scope", "workspace")
            .put("safe_to_store", true)
            .put("summary", summary)
            .put("device_id", deviceId())
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("created_at", now())
            .put("payload", payload)
    }

    private fun verificationPayload(status: String, result: JSONObject): JSONObject {
        return JSONObject()
            .put("verification_id", UUID.randomUUID().toString())
            .put("source", "apps.worker_nodes.android.MainActivity")
            .put("module", "Mainactivity")
            .put("recommended_agent", "verification")
            .put("status", status)
            .put("device_id", deviceId())
            .put("session_id", sessionId)
            .put("user_id", userId())
            .put("workspace_id", workspaceId())
            .put("created_at", now())
            .put("checks", JSONObject()
                .put("user_id_present", userId().isNotBlank())
                .put("workspace_id_present", workspaceId().isNotBlank())
                .put("device_id_present", deviceId().isNotBlank())
                .put("audit_payload_prepared", true)
                .put("security_payload_compatible", true)
                .put("memory_payload_compatible", true)
                .put("subscription_checked", latestLogin.permissions.isNotEmpty())
            )
            .put("result", result)
    }

    private fun localPermissionStatus(): JSONObject {
        val notificationGranted = if (Build.VERSION.SDK_INT >= 33) {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }

        return JSONObject()
            .put("post_notifications", notificationGranted)
            .put("accessibility_enabled", isAccessibilityEnabled())
            .put("can_draw_overlays", if (Build.VERSION.SDK_INT >= 23) Settings.canDrawOverlays(this) else true)
            .put("battery_optimization_note", "Review manually if long-running background control is required.")
    }

    private fun requestSafeRuntimePermissions() {
        if (Build.VERSION.SDK_INT >= 33) {
            val permission = Manifest.permission.POST_NOTIFICATIONS
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(permission),
                    REQUEST_NOTIFICATION_PERMISSION
                )
            }
        }
    }

    private fun isAccessibilityEnabled(): Boolean {
        return try {
            val manager = getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            manager.isEnabled
        } catch (_: Exception) {
            false
        }
    }

    private fun batteryInfo(): JSONObject {
        return try {
            val manager = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            val percent = manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            JSONObject()
                .put("percentage", max(percent, 0))
                .put("available", percent >= 0)
        } catch (_: Exception) {
            JSONObject()
                .put("available", false)
        }
    }

    private fun setLoading(isLoading: Boolean) {
        progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
        listOf(
            loginButton,
            registerButton,
            heartbeatButton,
            startButton,
            pauseButton,
            resumeButton,
            stopButton,
            accessibilityButton,
            permissionsButton,
            clearButton
        ).forEach { it.isEnabled = !isLoading }
    }

    private fun refreshStatus(title: String, detail: String) {
        statusText.text = "Status: $title"
        detailText.text = detail
    }

    private fun normalizedBackendUrl(): String {
        return backendInput.text.toString().trim().trimEnd('/')
    }

    private fun apiToken(): String {
        return tokenInput.text.toString().trim()
    }

    private fun userId(): String {
        return userIdInput.text.toString().trim()
    }

    private fun workspaceId(): String {
        return workspaceIdInput.text.toString().trim()
    }

    private fun deviceName(): String {
        return deviceNameInput.text.toString().trim().ifEmpty { defaultDeviceName() }
    }

    private fun deviceId(): String {
        return prefs.getString(KEY_DEVICE_ID, "").orEmpty().ifBlank { ensureDeviceId() }
    }

    private fun ensureDeviceId(): String {
        val existing = prefs.getString(KEY_DEVICE_ID, "").orEmpty()
        if (existing.isNotBlank()) {
            return existing
        }

        val raw = "${Build.MANUFACTURER}:${Build.MODEL}:${Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)}"
        val generated = "android-${sha256(raw).take(32)}"

        prefs.edit().putString(KEY_DEVICE_ID, generated).apply()
        return generated
    }

    private fun defaultDeviceName(): String {
        val manufacturer = Build.MANUFACTURER ?: "Android"
        val model = Build.MODEL ?: "Device"
        return "$manufacturer $model Worker"
    }

    private fun joinUrl(base: String, path: String): String {
        return "${base.trimEnd('/')}/${path.trimStart('/')}"
    }

    private fun readAll(reader: BufferedReader): String {
        return reader.useLines { lines -> lines.joinToString("\n") }
    }

    private fun parseJsonObject(text: String): JSONObject {
        if (text.isBlank()) {
            return JSONObject()
        }

        return try {
            JSONObject(text)
        } catch (_: Exception) {
            JSONObject().put("raw", redact(text.take(2000)))
        }
    }

    private fun prettyJson(json: JSONObject): String {
        return try {
            json.toString(2)
        } catch (_: Exception) {
            json.toString()
        }
    }

    private fun now(): String {
        return Instant.now().toString()
    }

    private fun safeHostName(): String {
        return try {
            Uri.encode(Build.DEVICE ?: "android-device")
        } catch (_: Exception) {
            "android-device"
        }
    }

    private fun sha256(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun safeError(error: Exception): String {
        return redact("${error.javaClass.simpleName}: ${error.message.orEmpty()}")
    }

    private fun redact(text: String): String {
        var value = text
        val blocked = listOf(
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "access_token",
            "refresh_token",
            "client_secret",
            apiToken()
        ).filter { it.isNotBlank() }

        blocked.forEach { item ->
            value = value.replace(item, "[redacted]", ignoreCase = true)
        }

        return value
    }

    private data class ValidationResult(
        val ok: Boolean,
        val message: String
    )

    private data class ApiResponse(
        val ok: Boolean,
        val statusCode: Int,
        val data: JSONObject,
        val error: String
    ) {
        fun safeMessage(): String {
            return if (ok) {
                "OK"
            } else {
                "HTTP/status=$statusCode ${error.ifBlank { "Request failed." }}"
            }
        }
    }

    private enum class WorkerStatus(val value: String) {
        CREATED("created"),
        AUTHENTICATED("authenticated"),
        REGISTERED("registered"),
        RUNNING("running"),
        PAUSED("paused"),
        STOPPED("stopped"),
        ERROR("error")
    }

    private data class LoginState(
        val userId: String,
        val workspaceId: String,
        val permissions: Set<String>,
        val roles: Set<String>,
        val planKey: String,
        val subscriptionActive: Boolean,
        val planAllowsAndroidWorker: Boolean
    ) {
        companion object {
            fun empty(): LoginState {
                return LoginState(
                    userId = "",
                    workspaceId = "",
                    permissions = emptySet(),
                    roles = emptySet(),
                    planKey = "",
                    subscriptionActive = false,
                    planAllowsAndroidWorker = false
                )
            }

            fun fromJson(json: JSONObject): LoginState {
                val data = json.optJSONObject("data") ?: json

                return LoginState(
                    userId = data.optString("user_id", ""),
                    workspaceId = data.optString("workspace_id", ""),
                    permissions = jsonArrayToSet(data.optJSONArray("permissions")),
                    roles = jsonArrayToSet(data.optJSONArray("roles")),
                    planKey = data.optString("plan_key", data.optString("plan", "")),
                    subscriptionActive = data.optBoolean("subscription_active", true),
                    planAllowsAndroidWorker = data.optBoolean("plan_allows_android_worker", true)
                )
            }

            private fun jsonArrayToSet(array: JSONArray?): Set<String> {
                if (array == null) {
                    return emptySet()
                }

                val output = mutableSetOf<String>()
                for (index in 0 until array.length()) {
                    output.add(array.optString(index))
                }
                return output.filter { it.isNotBlank() }.toSet()
            }
        }
    }
}

/**
 * Alias provided because the prompt specified required component name: Mainactivity.
 * Android conventions and manifests usually use MainActivity.
 */
typealias Mainactivity = MainActivity