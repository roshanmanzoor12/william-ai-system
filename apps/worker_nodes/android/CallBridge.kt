package com.digitalpromotix.william.worker

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.telecom.TelecomManager
import android.telephony.PhoneStateListener
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * CallBridge.kt
 *
 * Permission-based Android call detection and safe call handling bridge for
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.
 *
 * Purpose:
 * - Detect call state changes after explicit Android permission is granted.
 * - Report call events to backend with user_id and workspace_id isolation.
 * - Prepare audit, security, memory, and verification payloads.
 * - Support safe call handling with explicit permissions.
 *
 * Safety:
 * - No call recording.
 * - No stealth monitoring.
 * - No background call control without Android permissions.
 * - Phone numbers are redacted and hashed before reporting.
 * - ACTION_DIAL is used by default because it keeps the human in control.
 * - Direct ACTION_CALL is blocked unless explicitly enabled, permissioned, and security-approved.
 */
class CallBridge(
    private val context: Context,
    private val config: CallBridgeConfig = CallBridgeConfig.fromPreferences(context),
    private val eventSink: ((JSONObject) -> Unit)? = null,
    private val logger: ((String) -> Unit)? = null
) {

    private val appContext: Context = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    private val executor = Executors.newSingleThreadExecutor()
    private val isListening = AtomicBoolean(false)

    private var legacyListener: PhoneStateListener? = null
    private var modernCallback: TelephonyCallback? = null
    private var lastState: CallState = CallState.IDLE

    companion object {
        private const val PREF_NAME = "william_android_worker"

        private const val KEY_BACKEND_URL = "backend_url"
        private const val KEY_API_TOKEN = "api_token"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_WORKSPACE_ID = "workspace_id"
        private const val KEY_DEVICE_ID = "device_id"

        private const val DEFAULT_BACKEND_URL = "http://10.0.2.2:8000"

        private val REQUIRED_CALL_DETECTION_PERMISSIONS = setOf(
            "call.detect",
            "agents.call.use",
            "device.worker.android",
            "tasks.run"
        )

        private val REQUIRED_CALL_DIAL_PERMISSIONS = setOf(
            "call.dial",
            "agents.call.use",
            "device.worker.android",
            "tasks.run"
        )

        private val REQUIRED_DIRECT_CALL_PERMISSIONS = setOf(
            "call.place.direct",
            "agents.call.use",
            "security.approve",
            "device.worker.android",
            "tasks.run"
        )
    }

    fun startListening(request: CallBridgeRequest): CallBridgeResponse {
        val validation = validateRequest(
            request = request,
            requiredPermissions = REQUIRED_CALL_DETECTION_PERMISSIONS,
            action = "call_detection_start"
        )

        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Call detection start blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        if (!hasAndroidPermission(Manifest.permission.READ_PHONE_STATE)) {
            val response = deniedResponse(
                request = request,
                message = "Android READ_PHONE_STATE permission is required for call detection.",
                errors = jsonArrayOf(
                    jsonObjectOf(
                        "field" to "android_permission",
                        "error" to "missing_permission",
                        "permission" to Manifest.permission.READ_PHONE_STATE
                    )
                )
            )
            emit(response.toJson())
            return response
        }

        if (config.requireSecurityApprovalForDetection && request.securityApprovalId.isBlank()) {
            val response = needsApprovalResponse(
                request = request,
                action = "call_detection_start",
                riskLevel = RiskLevel.HIGH,
                message = "Call detection requires Security Agent approval."
            )
            emit(response.toJson())
            return response
        }

        return try {
            val telephonyManager =
                appContext.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val callback = object : TelephonyCallback(), TelephonyCallback.CallStateListener {
                    override fun onCallStateChanged(state: Int) {
                        handleRawCallState(state, null, request)
                    }
                }

                modernCallback = callback
                telephonyManager.registerTelephonyCallback(appContext.mainExecutor, callback)
            } else {
                @Suppress("DEPRECATION")
                val listener = object : PhoneStateListener() {
                    @Deprecated("Deprecated by Android; kept for legacy device compatibility.")
                    override fun onCallStateChanged(state: Int, phoneNumber: String?) {
                        handleRawCallState(state, phoneNumber, request)
                    }
                }

                legacyListener = listener
                @Suppress("DEPRECATION")
                telephonyManager.listen(listener, PhoneStateListener.LISTEN_CALL_STATE)
            }

            isListening.set(true)

            val audit = auditPayload(
                action = "android.call_bridge.listening_started",
                request = request,
                riskLevel = RiskLevel.HIGH,
                details = jsonObjectOf(
                    "android_permission_granted" to true,
                    "sdk_int" to Build.VERSION.SDK_INT
                )
            )

            val verification = verificationPayload(
                status = "call_detection_started",
                request = request,
                result = jsonObjectOf(
                    "listening" to true,
                    "device_id" to config.deviceId
                ),
                errors = JSONArray()
            )

            val response = CallBridgeResponse(
                ok = true,
                status = BridgeStatus.RUNNING,
                message = "Call detection started safely.",
                requestId = request.requestId,
                userId = request.userId,
                workspaceId = request.workspaceId,
                taskId = request.taskId,
                data = jsonObjectOf(
                    "listening" to true,
                    "android_permission" to Manifest.permission.READ_PHONE_STATE
                ),
                auditEvent = audit,
                securityPayload = securityPayload(
                    action = "call_detection_start",
                    request = request,
                    riskLevel = RiskLevel.HIGH,
                    requiresApproval = config.requireSecurityApprovalForDetection
                ),
                memoryPayload = memoryPayload(
                    summary = "Android call detection bridge started.",
                    request = request,
                    payload = jsonObjectOf("listening" to true)
                ),
                verificationPayload = verification
            )

            emit(response.toJson())
            response
        } catch (error: Exception) {
            val response = failedResponse(
                request = request,
                message = "Call detection failed safely.",
                error = error
            )
            emit(response.toJson())
            response
        }
    }

    fun stopListening(request: CallBridgeRequest): CallBridgeResponse {
        val validation = validateBasicIsolation(request)
        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Call detection stop blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        return try {
            val telephonyManager =
                appContext.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                modernCallback?.let { callback ->
                    telephonyManager.unregisterTelephonyCallback(callback)
                }
                modernCallback = null
            } else {
                legacyListener?.let { listener ->
                    @Suppress("DEPRECATION")
                    telephonyManager.listen(listener, PhoneStateListener.LISTEN_NONE)
                }
                legacyListener = null
            }

            isListening.set(false)
            lastState = CallState.IDLE

            val response = CallBridgeResponse(
                ok = true,
                status = BridgeStatus.STOPPED,
                message = "Call detection stopped safely.",
                requestId = request.requestId,
                userId = request.userId,
                workspaceId = request.workspaceId,
                taskId = request.taskId,
                data = jsonObjectOf("listening" to false),
                auditEvent = auditPayload(
                    action = "android.call_bridge.listening_stopped",
                    request = request,
                    riskLevel = RiskLevel.MEDIUM,
                    details = jsonObjectOf("listening" to false)
                ),
                verificationPayload = verificationPayload(
                    status = "call_detection_stopped",
                    request = request,
                    result = jsonObjectOf("listening" to false),
                    errors = JSONArray()
                )
            )

            emit(response.toJson())
            response
        } catch (error: Exception) {
            val response = failedResponse(
                request = request,
                message = "Stopping call detection failed safely.",
                error = error
            )
            emit(response.toJson())
            response
        }
    }

    fun dialNumber(request: CallBridgeRequest, phoneNumber: String): CallBridgeResponse {
        val validation = validateRequest(
            request = request,
            requiredPermissions = REQUIRED_CALL_DIAL_PERMISSIONS,
            action = "call_dial"
        )

        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Dial action blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        val normalizedPhone = normalizePhoneNumber(phoneNumber)
        if (normalizedPhone.isBlank()) {
            val response = deniedResponse(
                request = request,
                message = "Dial action blocked because phone number is invalid.",
                errors = jsonArrayOf(
                    jsonObjectOf(
                        "field" to "phone_number",
                        "error" to "invalid_or_empty"
                    )
                )
            )
            emit(response.toJson())
            return response
        }

        return try {
            val intent = Intent(Intent.ACTION_DIAL).apply {
                data = Uri.parse("tel:$normalizedPhone")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            appContext.startActivity(intent)

            val safePhone = safePhonePayload(normalizedPhone)
            val response = CallBridgeResponse(
                ok = true,
                status = BridgeStatus.SUCCESS,
                message = "Dialer opened with user control.",
                requestId = request.requestId,
                userId = request.userId,
                workspaceId = request.workspaceId,
                taskId = request.taskId,
                data = jsonObjectOf(
                    "action" to "ACTION_DIAL",
                    "phone" to safePhone
                ),
                auditEvent = auditPayload(
                    action = "android.call_bridge.dialer_opened",
                    request = request,
                    riskLevel = RiskLevel.HIGH,
                    details = jsonObjectOf(
                        "phone" to safePhone,
                        "human_confirmation_required" to true
                    )
                ),
                securityPayload = securityPayload(
                    action = "call_dial",
                    request = request,
                    riskLevel = RiskLevel.HIGH,
                    requiresApproval = false
                ),
                memoryPayload = memoryPayload(
                    summary = "Android dialer opened safely with user confirmation.",
                    request = request,
                    payload = jsonObjectOf("phone" to safePhone)
                ),
                verificationPayload = verificationPayload(
                    status = "dialer_opened",
                    request = request,
                    result = jsonObjectOf("phone" to safePhone),
                    errors = JSONArray()
                )
            )

            emit(response.toJson())
            response
        } catch (error: Exception) {
            val response = failedResponse(
                request = request,
                message = "Dial action failed safely.",
                error = error
            )
            emit(response.toJson())
            response
        }
    }

    fun placeDirectCall(request: CallBridgeRequest, phoneNumber: String): CallBridgeResponse {
        val validation = validateRequest(
            request = request,
            requiredPermissions = REQUIRED_DIRECT_CALL_PERMISSIONS,
            action = "call_place_direct"
        )

        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Direct call blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        if (!config.allowDirectCalls) {
            val response = deniedResponse(
                request = request,
                message = "Direct calling is disabled by local worker configuration. Use dialNumber instead.",
                errors = jsonArrayOf(
                    jsonObjectOf(
                        "field" to "allowDirectCalls",
                        "error" to "disabled"
                    )
                )
            )
            emit(response.toJson())
            return response
        }

        if (!hasAndroidPermission(Manifest.permission.CALL_PHONE)) {
            val response = deniedResponse(
                request = request,
                message = "Android CALL_PHONE permission is required for direct calls.",
                errors = jsonArrayOf(
                    jsonObjectOf(
                        "field" to "android_permission",
                        "error" to "missing_permission",
                        "permission" to Manifest.permission.CALL_PHONE
                    )
                )
            )
            emit(response.toJson())
            return response
        }

        if (request.securityApprovalId.isBlank()) {
            val response = needsApprovalResponse(
                request = request,
                action = "call_place_direct",
                riskLevel = RiskLevel.CRITICAL,
                message = "Direct call requires Security Agent approval."
            )
            emit(response.toJson())
            return response
        }

        val normalizedPhone = normalizePhoneNumber(phoneNumber)
        if (normalizedPhone.isBlank()) {
            val response = deniedResponse(
                request = request,
                message = "Direct call blocked because phone number is invalid.",
                errors = jsonArrayOf(
                    jsonObjectOf(
                        "field" to "phone_number",
                        "error" to "invalid_or_empty"
                    )
                )
            )
            emit(response.toJson())
            return response
        }

        return try {
            val intent = Intent(Intent.ACTION_CALL).apply {
                data = Uri.parse("tel:$normalizedPhone")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            appContext.startActivity(intent)

            val safePhone = safePhonePayload(normalizedPhone)
            val response = CallBridgeResponse(
                ok = true,
                status = BridgeStatus.SUCCESS,
                message = "Direct call started after permission and security approval.",
                requestId = request.requestId,
                userId = request.userId,
                workspaceId = request.workspaceId,
                taskId = request.taskId,
                data = jsonObjectOf(
                    "action" to "ACTION_CALL",
                    "phone" to safePhone,
                    "security_approval_id" to request.securityApprovalId
                ),
                auditEvent = auditPayload(
                    action = "android.call_bridge.direct_call_started",
                    request = request,
                    riskLevel = RiskLevel.CRITICAL,
                    details = jsonObjectOf(
                        "phone" to safePhone,
                        "security_approval_id" to request.securityApprovalId
                    )
                ),
                securityPayload = securityPayload(
                    action = "call_place_direct",
                    request = request,
                    riskLevel = RiskLevel.CRITICAL,
                    requiresApproval = true
                ),
                verificationPayload = verificationPayload(
                    status = "direct_call_started",
                    request = request,
                    result = jsonObjectOf("phone" to safePhone),
                    errors = JSONArray()
                )
            )

            emit(response.toJson())
            response
        } catch (error: Exception) {
            val response = failedResponse(
                request = request,
                message = "Direct call failed safely.",
                error = error
            )
            emit(response.toJson())
            response
        }
    }

    fun openCallSettings(request: CallBridgeRequest): CallBridgeResponse {
        val validation = validateBasicIsolation(request)
        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Opening call settings blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        return try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${appContext.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            appContext.startActivity(intent)

            val response = CallBridgeResponse(
                ok = true,
                status = BridgeStatus.SUCCESS,
                message = "Opened app settings so user can review permissions.",
                requestId = request.requestId,
                userId = request.userId,
                workspaceId = request.workspaceId,
                taskId = request.taskId,
                data = jsonObjectOf("opened_settings" to true),
                auditEvent = auditPayload(
                    action = "android.call_bridge.permission_settings_opened",
                    request = request,
                    riskLevel = RiskLevel.MEDIUM,
                    details = jsonObjectOf("package" to appContext.packageName)
                ),
                verificationPayload = verificationPayload(
                    status = "permission_settings_opened",
                    request = request,
                    result = jsonObjectOf("opened_settings" to true),
                    errors = JSONArray()
                )
            )

            emit(response.toJson())
            response
        } catch (error: Exception) {
            val response = failedResponse(
                request = request,
                message = "Opening app settings failed safely.",
                error = error
            )
            emit(response.toJson())
            response
        }
    }

    fun checkPermissions(request: CallBridgeRequest): CallBridgeResponse {
        val validation = validateBasicIsolation(request)
        if (!validation.ok) {
            val response = deniedResponse(
                request = request,
                message = "Permission check blocked by validation.",
                errors = validation.errors
            )
            emit(response.toJson())
            return response
        }

        val result = jsonObjectOf(
            "android_permissions" to androidPermissionStatus(),
            "backend_required_call_detection_permissions" to JSONArray(REQUIRED_CALL_DETECTION_PERMISSIONS.toList()),
            "backend_required_call_dial_permissions" to JSONArray(REQUIRED_CALL_DIAL_PERMISSIONS.toList()),
            "backend_required_direct_call_permissions" to JSONArray(REQUIRED_DIRECT_CALL_PERMISSIONS.toList()),
            "config" to config.safeJson()
        )

        val response = CallBridgeResponse(
            ok = true,
            status = BridgeStatus.SUCCESS,
            message = "Call bridge permissions checked.",
            requestId = request.requestId,
            userId = request.userId,
            workspaceId = request.workspaceId,
            taskId = request.taskId,
            data = result,
            auditEvent = auditPayload(
                action = "android.call_bridge.permissions_checked",
                request = request,
                riskLevel = RiskLevel.LOW,
                details = result
            ),
            verificationPayload = verificationPayload(
                status = "call_bridge_permissions_checked",
                request = request,
                result = result,
                errors = JSONArray()
            )
        )

        emit(response.toJson())
        return response
    }

    fun isRunning(): Boolean {
        return isListening.get()
    }

    fun shutdown() {
        executor.shutdownNow()
    }

    private fun handleRawCallState(rawState: Int, rawPhoneNumber: String?, request: CallBridgeRequest) {
        val state = when (rawState) {
            TelephonyManager.CALL_STATE_RINGING -> CallState.RINGING
            TelephonyManager.CALL_STATE_OFFHOOK -> CallState.OFFHOOK
            TelephonyManager.CALL_STATE_IDLE -> CallState.IDLE
            else -> CallState.UNKNOWN
        }

        if (state == lastState) {
            return
        }

        lastState = state

        val phone = if (config.includePhoneNumberHash && !rawPhoneNumber.isNullOrBlank()) {
            safePhonePayload(rawPhoneNumber)
        } else {
            jsonObjectOf(
                "available" to false,
                "redacted" to true,
                "reason" to "phone_number_not_available_or_disabled"
            )
        }

        val event = jsonObjectOf(
            "event_id" to UUID.randomUUID().toString(),
            "event_type" to "call_state_changed",
            "source" to "apps.worker_nodes.android.CallBridge",
            "module" to "Callbridge",
            "device_id" to config.deviceId,
            "user_id" to request.userId,
            "workspace_id" to request.workspaceId,
            "task_id" to request.taskId,
            "request_id" to request.requestId,
            "call_state" to state.value,
            "previous_state" to lastState.value,
            "phone" to phone,
            "created_at" to now(),
            "audit_event" to auditPayload(
                action = "android.call_bridge.call_state_changed",
                request = request,
                riskLevel = RiskLevel.HIGH,
                details = jsonObjectOf(
                    "call_state" to state.value,
                    "phone" to phone
                )
            ),
            "security_payload" to securityPayload(
                action = "call_state_detection",
                request = request,
                riskLevel = RiskLevel.HIGH,
                requiresApproval = config.requireSecurityApprovalForDetection
            ),
            "memory_payload" to memoryPayload(
                summary = "Android call state changed.",
                request = request,
                payload = jsonObjectOf(
                    "call_state" to state.value,
                    "phone" to phone
                )
            ),
            "verification_payload" to verificationPayload(
                status = "call_state_detected",
                request = request,
                result = jsonObjectOf(
                    "call_state" to state.value,
                    "phone" to phone
                ),
                errors = JSONArray()
            )
        )

        emit(event)

        if (config.reportEventsToBackend) {
            executor.execute {
                postToBackend("/api/worker/android/call-event", event)
            }
        }
    }

    private fun validateRequest(
        request: CallBridgeRequest,
        requiredPermissions: Set<String>,
        action: String
    ): ValidationResult {
        val base = validateBasicIsolation(request)
        val errors = JSONArray()

        for (index in 0 until base.errors.length()) {
            errors.put(base.errors.getJSONObject(index))
        }

        val missingPermissions = requiredPermissions.filterNot { request.permissions.contains(it) }
        if (missingPermissions.isNotEmpty()) {
            errors.put(
                jsonObjectOf(
                    "field" to "permissions",
                    "error" to "missing_required_permissions",
                    "action" to action,
                    "missing_permissions" to JSONArray(missingPermissions)
                )
            )
        }

        if (!request.subscriptionActive) {
            errors.put(
                jsonObjectOf(
                    "field" to "subscription",
                    "error" to "inactive_subscription"
                )
            )
        }

        if (!request.planAllowsCallBridge) {
            errors.put(
                jsonObjectOf(
                    "field" to "plan",
                    "error" to "plan_does_not_allow_call_bridge"
                )
            )
        }

        return ValidationResult(
            ok = errors.length() == 0,
            message = if (errors.length() == 0) "Valid." else "Validation failed.",
            errors = errors
        )
    }

    private fun validateBasicIsolation(request: CallBridgeRequest): ValidationResult {
        val errors = JSONArray()

        if (request.userId.isBlank()) {
            errors.put(jsonObjectOf("field" to "user_id", "error" to "required"))
        }

        if (request.workspaceId.isBlank()) {
            errors.put(jsonObjectOf("field" to "workspace_id", "error" to "required"))
        }

        if (request.requestedByUserId.isBlank()) {
            errors.put(jsonObjectOf("field" to "requested_by_user_id", "error" to "required"))
        }

        if (request.taskId.isBlank()) {
            errors.put(jsonObjectOf("field" to "task_id", "error" to "required"))
        }

        if (config.userId.isNotBlank() && request.userId != config.userId) {
            errors.put(
                jsonObjectOf(
                    "field" to "user_id",
                    "error" to "isolation_violation",
                    "detail" to "Request user_id does not match Android worker user_id."
                )
            )
        }

        if (config.workspaceId.isNotBlank() && request.workspaceId != config.workspaceId) {
            errors.put(
                jsonObjectOf(
                    "field" to "workspace_id",
                    "error" to "isolation_violation",
                    "detail" to "Request workspace_id does not match Android worker workspace_id."
                )
            )
        }

        return ValidationResult(
            ok = errors.length() == 0,
            message = if (errors.length() == 0) "Valid." else "Isolation validation failed.",
            errors = errors
        )
    }

    private fun deniedResponse(
        request: CallBridgeRequest,
        message: String,
        errors: JSONArray
    ): CallBridgeResponse {
        return CallBridgeResponse(
            ok = false,
            status = BridgeStatus.DENIED,
            message = message,
            requestId = request.requestId,
            userId = request.userId,
            workspaceId = request.workspaceId,
            taskId = request.taskId,
            errors = errors,
            auditEvent = auditPayload(
                action = "android.call_bridge.denied",
                request = request,
                riskLevel = RiskLevel.HIGH,
                details = jsonObjectOf("errors" to errors)
            ),
            verificationPayload = verificationPayload(
                status = "denied",
                request = request,
                result = JSONObject(),
                errors = errors
            )
        )
    }

    private fun needsApprovalResponse(
        request: CallBridgeRequest,
        action: String,
        riskLevel: RiskLevel,
        message: String
    ): CallBridgeResponse {
        return CallBridgeResponse(
            ok = false,
            status = BridgeStatus.NEEDS_APPROVAL,
            message = message,
            requestId = request.requestId,
            userId = request.userId,
            workspaceId = request.workspaceId,
            taskId = request.taskId,
            errors = jsonArrayOf(
                jsonObjectOf(
                    "error" to "security_approval_required",
                    "action" to action
                )
            ),
            auditEvent = auditPayload(
                action = "android.call_bridge.needs_approval",
                request = request,
                riskLevel = riskLevel,
                details = jsonObjectOf("action" to action)
            ),
            securityPayload = securityPayload(
                action = action,
                request = request,
                riskLevel = riskLevel,
                requiresApproval = true
            )
        )
    }

    private fun failedResponse(
        request: CallBridgeRequest,
        message: String,
        error: Exception
    ): CallBridgeResponse {
        val errors = jsonArrayOf(
            jsonObjectOf(
                "error" to error.javaClass.simpleName,
                "message" to redact(error.message.orEmpty())
            )
        )

        return CallBridgeResponse(
            ok = false,
            status = BridgeStatus.FAILED,
            message = message,
            requestId = request.requestId,
            userId = request.userId,
            workspaceId = request.workspaceId,
            taskId = request.taskId,
            errors = errors,
            auditEvent = auditPayload(
                action = "android.call_bridge.failed",
                request = request,
                riskLevel = RiskLevel.HIGH,
                details = jsonObjectOf("errors" to errors)
            ),
            verificationPayload = verificationPayload(
                status = "failed",
                request = request,
                result = JSONObject(),
                errors = errors
            )
        )
    }

    private fun auditPayload(
        action: String,
        request: CallBridgeRequest,
        riskLevel: RiskLevel,
        details: JSONObject
    ): JSONObject {
        return jsonObjectOf(
            "event_id" to UUID.randomUUID().toString(),
            "event_type" to "audit",
            "source" to "apps.worker_nodes.android.CallBridge",
            "module" to "Callbridge",
            "action" to action,
            "risk_level" to riskLevel.value,
            "device_id" to config.deviceId,
            "actor_user_id" to request.requestedByUserId,
            "user_id" to request.userId,
            "workspace_id" to request.workspaceId,
            "task_id" to request.taskId,
            "request_id" to request.requestId,
            "created_at" to now(),
            "details" to details
        )
    }

    private fun securityPayload(
        action: String,
        request: CallBridgeRequest,
        riskLevel: RiskLevel,
        requiresApproval: Boolean
    ): JSONObject {
        return jsonObjectOf(
            "security_request_id" to UUID.randomUUID().toString(),
            "source" to "apps.worker_nodes.android.CallBridge",
            "module" to "Callbridge",
            "recommended_agent" to "security",
            "action" to action,
            "risk_level" to riskLevel.value,
            "requires_approval" to requiresApproval,
            "security_approval_id" to request.securityApprovalId,
            "device_id" to config.deviceId,
            "actor_user_id" to request.requestedByUserId,
            "user_id" to request.userId,
            "workspace_id" to request.workspaceId,
            "task_id" to request.taskId,
            "request_id" to request.requestId,
            "created_at" to now(),
            "policy" to jsonObjectOf(
                "must_match_user_id" to true,
                "must_match_workspace_id" to true,
                "must_check_android_permissions" to true,
                "must_check_subscription" to true,
                "must_check_role_permissions" to true,
                "no_call_recording" to true,
                "redact_phone_number" to true
            )
        )
    }

    private fun memoryPayload(
        summary: String,
        request: CallBridgeRequest,
        payload: JSONObject
    ): JSONObject {
        return jsonObjectOf(
            "memory_event_id" to UUID.randomUUID().toString(),
            "source" to "apps.worker_nodes.android.CallBridge",
            "module" to "Callbridge",
            "recommended_agent" to "memory",
            "memory_scope" to "workspace",
            "safe_to_store" to true,
            "summary" to summary,
            "device_id" to config.deviceId,
            "user_id" to request.userId,
            "workspace_id" to request.workspaceId,
            "task_id" to request.taskId,
            "request_id" to request.requestId,
            "created_at" to now(),
            "payload" to payload
        )
    }

    private fun verificationPayload(
        status: String,
        request: CallBridgeRequest,
        result: JSONObject,
        errors: JSONArray
    ): JSONObject {
        return jsonObjectOf(
            "verification_id" to UUID.randomUUID().toString(),
            "source" to "apps.worker_nodes.android.CallBridge",
            "module" to "Callbridge",
            "recommended_agent" to "verification",
            "status" to status,
            "device_id" to config.deviceId,
            "user_id" to request.userId,
            "workspace_id" to request.workspaceId,
            "task_id" to request.taskId,
            "request_id" to request.requestId,
            "created_at" to now(),
            "checks" to jsonObjectOf(
                "user_id_present" to request.userId.isNotBlank(),
                "workspace_id_present" to request.workspaceId.isNotBlank(),
                "task_id_present" to request.taskId.isNotBlank(),
                "worker_user_match" to (config.userId.isBlank() || request.userId == config.userId),
                "worker_workspace_match" to (config.workspaceId.isBlank() || request.workspaceId == config.workspaceId),
                "audit_payload_prepared" to true,
                "security_payload_compatible" to true,
                "memory_payload_compatible" to true,
                "phone_number_redacted" to true,
                "call_recording_disabled" to true
            ),
            "result" to result,
            "errors" to errors
        )
    }

    private fun postToBackend(path: String, payload: JSONObject): ApiResponse {
        if (config.backendUrl.isBlank() || config.apiToken.isBlank()) {
            return ApiResponse(false, 0, JSONObject(), "Backend URL or API token missing.")
        }

        return try {
            val url = URL(joinUrl(config.backendUrl, path))
            val connection = url.openConnection() as HttpURLConnection

            connection.requestMethod = "POST"
            connection.connectTimeout = config.connectTimeoutMs
            connection.readTimeout = config.readTimeoutMs
            connection.doOutput = true
            connection.doInput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${config.apiToken}")
            connection.setRequestProperty("X-Device-Id", config.deviceId)
            connection.setRequestProperty("X-User-Id", config.userId)
            connection.setRequestProperty("X-Workspace-Id", config.workspaceId)
            connection.setRequestProperty("X-Request-Id", UUID.randomUUID().toString())

            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(payload.toString())
                writer.flush()
            }

            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.let { readAll(it) }.orEmpty()

            ApiResponse(
                ok = statusCode in 200..299,
                statusCode = statusCode,
                data = parseJsonObject(body),
                error = if (statusCode in 200..299) "" else redact(body)
            )
        } catch (error: Exception) {
            ApiResponse(
                ok = false,
                statusCode = 0,
                data = JSONObject(),
                error = redact("${error.javaClass.simpleName}: ${error.message.orEmpty()}")
            )
        }
    }

    private fun androidPermissionStatus(): JSONObject {
        return jsonObjectOf(
            Manifest.permission.READ_PHONE_STATE to hasAndroidPermission(Manifest.permission.READ_PHONE_STATE),
            Manifest.permission.CALL_PHONE to hasAndroidPermission(Manifest.permission.CALL_PHONE),
            "default_dialer" to isDefaultDialer(),
            "listening" to isListening.get()
        )
    }

    private fun isDefaultDialer(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val telecomManager =
                    appContext.getSystemService(Context.TELECOM_SERVICE) as TelecomManager
                telecomManager.defaultDialerPackage == appContext.packageName
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun hasAndroidPermission(permission: String): Boolean {
        return ContextCompat.checkSelfPermission(appContext, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun emit(payload: JSONObject) {
        eventSink?.invoke(payload)

        if (config.reportEventsToBackend && payload.optString("event_type") != "backend_report") {
            executor.execute {
                postToBackend("/api/worker/android/call-event", payload)
            }
        }

        logger?.invoke(redact(payload.toString()))
    }

    private fun safePhonePayload(phoneNumber: String): JSONObject {
        val normalized = normalizePhoneNumber(phoneNumber)
        return jsonObjectOf(
            "available" to normalized.isNotBlank(),
            "redacted" to true,
            "last4" to normalized.takeLast(4).ifBlank { "" },
            "sha256" to sha256("${config.workspaceId}:$normalized"),
            "display" to maskedPhone(normalized)
        )
    }

    private fun normalizePhoneNumber(phoneNumber: String): String {
        val allowed = phoneNumber.trim().filter { character ->
            character.isDigit() || character == '+'
        }

        if (allowed.count { it == '+' } > 1) {
            return ""
        }

        if (allowed.contains("+") && !allowed.startsWith("+")) {
            return ""
        }

        return allowed.take(24)
    }

    private fun maskedPhone(phoneNumber: String): String {
        if (phoneNumber.isBlank()) {
            return ""
        }

        val last4 = phoneNumber.takeLast(4)
        return "••••••$last4"
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
            jsonObjectOf("raw" to redact(text.take(2000)))
        }
    }

    private fun now(): String {
        return Instant.now().toString()
    }

    private fun sha256(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
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
            config.apiToken
        ).filter { it.isNotBlank() }

        blocked.forEach { item ->
            value = value.replace(item, "[redacted]", ignoreCase = true)
        }

        return value
    }

    private fun jsonObjectOf(vararg pairs: Pair<String, Any?>): JSONObject {
        val json = JSONObject()
        pairs.forEach { pair ->
            val value = pair.second
            when (value) {
                null -> json.put(pair.first, JSONObject.NULL)
                is JSONObject -> json.put(pair.first, value)
                is JSONArray -> json.put(pair.first, value)
                is Collection<*> -> json.put(pair.first, JSONArray(value))
                is Array<*> -> json.put(pair.first, JSONArray(value.toList()))
                else -> json.put(pair.first, value)
            }
        }
        return json
    }

    private fun jsonArrayOf(vararg values: Any?): JSONArray {
        val array = JSONArray()
        values.forEach { value ->
            when (value) {
                null -> array.put(JSONObject.NULL)
                is JSONObject -> array.put(value)
                is JSONArray -> array.put(value)
                is Collection<*> -> array.put(JSONArray(value))
                is Array<*> -> array.put(JSONArray(value.toList()))
                else -> array.put(value)
            }
        }
        return array
    }

    data class CallBridgeConfig(
        val backendUrl: String,
        val apiToken: String,
        val userId: String,
        val workspaceId: String,
        val deviceId: String,
        val requireSecurityApprovalForDetection: Boolean = true,
        val allowDirectCalls: Boolean = false,
        val includePhoneNumberHash: Boolean = true,
        val reportEventsToBackend: Boolean = true,
        val connectTimeoutMs: Int = 15000,
        val readTimeoutMs: Int = 20000
    ) {
        fun safeJson(): JSONObject {
            return JSONObject()
                .put("backend_url_present", backendUrl.isNotBlank())
                .put("api_token_present", apiToken.isNotBlank())
                .put("user_id", userId)
                .put("workspace_id", workspaceId)
                .put("device_id", deviceId)
                .put("require_security_approval_for_detection", requireSecurityApprovalForDetection)
                .put("allow_direct_calls", allowDirectCalls)
                .put("include_phone_number_hash", includePhoneNumberHash)
                .put("report_events_to_backend", reportEventsToBackend)
        }

        companion object {
            fun fromPreferences(context: Context): CallBridgeConfig {
                val prefs = context.applicationContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
                val androidId = Settings.Secure.getString(
                    context.contentResolver,
                    Settings.Secure.ANDROID_ID
                ).orEmpty()

                val fallbackDeviceId = "android-${sha256Static("${Build.MANUFACTURER}:${Build.MODEL}:$androidId").take(32)}"

                return CallBridgeConfig(
                    backendUrl = prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL).orEmpty(),
                    apiToken = prefs.getString(KEY_API_TOKEN, "").orEmpty(),
                    userId = prefs.getString(KEY_USER_ID, "").orEmpty(),
                    workspaceId = prefs.getString(KEY_WORKSPACE_ID, "").orEmpty(),
                    deviceId = prefs.getString(KEY_DEVICE_ID, fallbackDeviceId).orEmpty().ifBlank { fallbackDeviceId }
                )
            }

            private fun sha256Static(text: String): String {
                val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
                return digest.joinToString("") { "%02x".format(it) }
            }
        }
    }

    data class CallBridgeRequest(
        val userId: String,
        val workspaceId: String,
        val taskId: String,
        val requestedByUserId: String,
        val permissions: Set<String>,
        val roles: Set<String> = emptySet(),
        val planKey: String = "",
        val subscriptionActive: Boolean = true,
        val planAllowsCallBridge: Boolean = true,
        val securityApprovalId: String = "",
        val requestId: String = UUID.randomUUID().toString(),
        val metadata: JSONObject = JSONObject()
    ) {
        fun toJson(): JSONObject {
            return JSONObject()
                .put("user_id", userId)
                .put("workspace_id", workspaceId)
                .put("task_id", taskId)
                .put("requested_by_user_id", requestedByUserId)
                .put("permissions", JSONArray(permissions.toList()))
                .put("roles", JSONArray(roles.toList()))
                .put("plan_key", planKey)
                .put("subscription_active", subscriptionActive)
                .put("plan_allows_call_bridge", planAllowsCallBridge)
                .put("security_approval_id", securityApprovalId)
                .put("request_id", requestId)
                .put("metadata", metadata)
        }

        companion object {
            fun fromJson(json: JSONObject): CallBridgeRequest {
                return CallBridgeRequest(
                    userId = json.optString("user_id", ""),
                    workspaceId = json.optString("workspace_id", ""),
                    taskId = json.optString("task_id", ""),
                    requestedByUserId = json.optString("requested_by_user_id", json.optString("user_id", "")),
                    permissions = jsonArrayToSet(json.optJSONArray("permissions")),
                    roles = jsonArrayToSet(json.optJSONArray("roles")),
                    planKey = json.optString("plan_key", ""),
                    subscriptionActive = json.optBoolean("subscription_active", true),
                    planAllowsCallBridge = json.optBoolean("plan_allows_call_bridge", true),
                    securityApprovalId = json.optString("security_approval_id", ""),
                    requestId = json.optString("request_id", UUID.randomUUID().toString()),
                    metadata = json.optJSONObject("metadata") ?: JSONObject()
                )
            }

            private fun jsonArrayToSet(array: JSONArray?): Set<String> {
                if (array == null) {
                    return emptySet()
                }

                val output = mutableSetOf<String>()
                for (index in 0 until array.length()) {
                    val value = array.optString(index)
                    if (value.isNotBlank()) {
                        output.add(value)
                    }
                }
                return output
            }
        }
    }

    data class CallBridgeResponse(
        val ok: Boolean,
        val status: BridgeStatus,
        val message: String,
        val requestId: String,
        val userId: String,
        val workspaceId: String,
        val taskId: String,
        val data: JSONObject = JSONObject(),
        val errors: JSONArray = JSONArray(),
        val auditEvent: JSONObject? = null,
        val securityPayload: JSONObject? = null,
        val memoryPayload: JSONObject? = null,
        val verificationPayload: JSONObject? = null,
        val createdAt: String = Instant.now().toString()
    ) {
        fun toJson(): JSONObject {
            val json = JSONObject()
                .put("ok", ok)
                .put("status", status.value)
                .put("message", message)
                .put("request_id", requestId)
                .put("user_id", userId)
                .put("workspace_id", workspaceId)
                .put("task_id", taskId)
                .put("data", data)
                .put("errors", errors)
                .put("created_at", createdAt)

            auditEvent?.let { json.put("audit_event", it) }
            securityPayload?.let { json.put("security_payload", it) }
            memoryPayload?.let { json.put("memory_payload", it) }
            verificationPayload?.let { json.put("verification_payload", it) }

            return json
        }
    }

    data class ValidationResult(
        val ok: Boolean,
        val message: String,
        val errors: JSONArray
    )

    data class ApiResponse(
        val ok: Boolean,
        val statusCode: Int,
        val data: JSONObject,
        val error: String
    )

    enum class BridgeStatus(val value: String) {
        SUCCESS("success"),
        RUNNING("running"),
        STOPPED("stopped"),
        DENIED("denied"),
        NEEDS_APPROVAL("needs_approval"),
        FAILED("failed")
    }

    enum class RiskLevel(val value: String) {
        LOW("low"),
        MEDIUM("medium"),
        HIGH("high"),
        CRITICAL("critical")
    }

    enum class CallState(val value: String) {
        IDLE("idle"),
        RINGING("ringing"),
        OFFHOOK("offhook"),
        UNKNOWN("unknown")
    }
}

/**
 * Alias provided because the prompt specified required component name: Callbridge.
 * Kotlin/Android convention uses CallBridge.
 */
typealias Callbridge = CallBridge