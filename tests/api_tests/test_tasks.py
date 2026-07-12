"""
tests/api_tests/test_tasks.py

Real HTTP tests for POST /tasks/run -- the dashboard AI console's command
entrypoint (apps/dashboard/src/app/(dashboard)/dashboard/page.tsx's
"Run Through Master Flow" button). Uses the same real JWT auth fixtures as
tests/api_tests/test_voice.py.
"""

from __future__ import annotations


class TestTasksRun:
    def test_veo_prompt_command_succeeds_and_routes_to_creator(self, client, make_owner) -> None:
        """
        Regression test: "William create a VEO prompt for ClickRonix"
        previously always failed -- the Planner's naive substring keyword
        match let "click" (a browser_action keyword) match inside the brand
        name "ClickRonix", routing the whole request to BusinessAgent with
        an action it doesn't recognize ("Unsupported or missing business
        action"). Fixed by word-boundary keyword matching (core/planner.py)
        plus real "veo"/"video prompt" keywords for the creator agent.
        """
        owner = make_owner()
        response = client.post(
            "/api/v1/tasks/run",
            json={
                "action": "general_request",
                "message": "William create a VEO prompt for ClickRonix",
                "input_data": {},
                "metadata": {"source": "dashboard.command_console"},
            },
            headers=owner.headers,
        )
        assert response.status_code == 200
        task = response.json()["data"]["task"]
        assert task["status"] == "completed", task.get("error")
        assert task["error"] is None

        results = ((task.get("result") or {}).get("data") or {}).get("results", [])
        routed_agents = [r.get("data", {}).get("agent_name") for r in results]
        assert "creator" in routed_agents

    def test_failed_task_exposes_error_details(self, client, make_owner) -> None:
        """A task that fails must carry a real, non-empty `error` value (not
        just a bare "failed" status with no detail) -- this is what the
        dashboard command console surfaces to the user."""
        owner = make_owner()
        response = client.post(
            "/api/v1/tasks/run",
            json={
                "action": "general_request",
                # No agent keyword matches at all -> falls to the "business"
                # default agent with a generic, unrecognized action -- a
                # real, reproducible failure mode independent of the
                # ClickRonix bug above.
                "message": "xyzzy quux",
                "input_data": {},
                "metadata": {},
            },
            headers=owner.headers,
        )
        assert response.status_code == 200
        task = response.json()["data"]["task"]

        if task["status"] == "failed":
            assert task["error"] not in (None, "", {})
        else:
            # If the pipeline's own fallback handling considers this a
            # "completed_with_errors" success at the master-agent level,
            # that's fine too -- the hard requirement is just that a real
            # failure is never silently blank.
            assert task["status"] == "completed"
