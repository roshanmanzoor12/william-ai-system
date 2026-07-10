# test_security_module.py

import os
import json
from pathlib import Path

from security.secrets_manager import SecretsManager
from security.encryption import EncryptionManager


def print_result(title, result):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print(json.dumps(result, indent=2, default=str))


def main():
    print("William/Jarvis Security Utility Smoke Test Started")

    # 1. Test SecretsManager
    os.environ["WILLIAM_TEST_API_KEY"] = "this-is-a-test-secret-value"

    secrets_manager = SecretsManager()

    secret_result = secrets_manager.get_secret(
        "TEST_API_KEY",
        user_id="user_001",
        workspace_id="workspace_001",
        scoped=False,
        include_value=False
    )

    print_result("1. SecretsManager - Safe Secret Check", secret_result)

    # 2. Test EncryptionManager key generation
    encryption_manager = EncryptionManager()

    key_result = encryption_manager.generate_key()
    print_result("2. EncryptionManager - Generate Key", {
        "success": key_result["success"],
        "message": key_result["message"],
        "data": {
            "key_id": key_result["data"].get("key_id"),
            "encoding": key_result["data"].get("encoding"),
            "bytes": key_result["data"].get("bytes"),
            "key_preview": str(key_result["data"].get("key"))[:8] + "***"
        },
        "error": key_result["error"],
        "metadata": key_result["metadata"]
    })

    # Put generated key into environment for encryption test
    os.environ["WILLIAM_ENCRYPTION_KEY"] = key_result["data"]["key"]
    os.environ["WILLIAM_ENCRYPTION_KEY_ID"] = "local-test-key-v1"

    # Recreate manager so it sees env key cleanly
    encryption_manager = EncryptionManager()

    # 3. Encrypt scoped data
    encrypted = encryption_manager.encrypt_text(
        "This is private workspace memory data.",
        user_id="user_001",
        workspace_id="workspace_001",
        scoped=True,
        purpose="memory"
    )

    print_result("3. EncryptionManager - Encrypt Text", {
        "success": encrypted["success"],
        "message": encrypted["message"],
        "data": {
            "token_preview": encrypted["data"].get("token", "")[:32] + "***",
            "algorithm": encrypted["data"].get("algorithm"),
            "key_id": encrypted["data"].get("key_id"),
            "aad_hash": encrypted["data"].get("aad_hash")
        },
        "error": encrypted["error"],
        "metadata": encrypted["metadata"]
    })

    # 4. Decrypt with correct user/workspace
    decrypted = encryption_manager.decrypt_text(
        encrypted["data"]["token"],
        user_id="user_001",
        workspace_id="workspace_001",
        scoped=True,
        purpose="memory"
    )

    print_result("4. EncryptionManager - Decrypt Correct Context", decrypted)

    # 5. Try decrypting with wrong user — should fail
    wrong_context = encryption_manager.decrypt_text(
        encrypted["data"]["token"],
        user_id="user_999",
        workspace_id="workspace_001",
        scoped=True,
        purpose="memory"
    )

    print_result("5. EncryptionManager - Wrong User Context Should Fail", wrong_context)

    # 6. Validate policy JSON
    policy_path = Path("security/policies/default_policy.json")

    with policy_path.open("r", encoding="utf-8") as file:
        policy = json.load(file)

    policy_check = {
        "success": True,
        "message": "Default policy JSON loaded successfully.",
        "data": {
            "policy_name": policy["policy_metadata"]["policy_name"],
            "contains_secrets": policy["policy_metadata"]["contains_secrets"],
            "unknown_action_default": policy["default_decision"]["unknown_action"],
            "saas_isolation_required": policy["global_principles"]["saas_isolation_required"],
            "blocked_action_groups": list(policy["blocked_actions"].keys())
        },
        "error": None,
        "metadata": {
            "file": str(policy_path)
        }
    }

    print_result("6. Policy JSON - Validation", policy_check)

    print("\nWilliam/Jarvis Security Utility Smoke Test Finished")


if __name__ == "__main__":
    main()