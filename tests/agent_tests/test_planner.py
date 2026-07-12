"""
tests/agent_tests/test_planner.py

Regression tests for core/planner.py's keyword-based intent detection.
"""

from __future__ import annotations

from core.planner import Planner


class TestPlannerKeywordMatching:
    def test_click_does_not_match_inside_brand_name(self) -> None:
        """
        "ClickRonix" (a brand name) previously matched the browser_action
        keyword "click" via a raw substring check, silently routing
        "William create a VEO prompt for ClickRonix" to BusinessAgent with
        an action it doesn't recognize instead of the Creator Agent. Fixed
        with word-boundary keyword matching.
        """
        planner = Planner()
        result = planner.detect_intent(message="William create a VEO prompt for ClickRonix", action="general_request")
        assert result["success"] is True
        assert result["data"]["primary_agent"] == "creator"
        assert result["data"]["action"] != "browser_action"

    def test_click_still_matches_as_a_real_word(self) -> None:
        """The word-boundary fix must not break real matches -- "click" on
        its own still triggers browser_action."""
        planner = Planner()
        result = planner.detect_intent(message="please click the submit button on our site", action="general_request")
        assert result["data"]["action"] == "browser_action"

    def test_veo_prompt_routes_to_creator(self) -> None:
        planner = Planner()
        result = planner.detect_intent(message="Make a VEO prompt for our new product launch", action="general_request")
        assert result["data"]["primary_agent"] == "creator"
