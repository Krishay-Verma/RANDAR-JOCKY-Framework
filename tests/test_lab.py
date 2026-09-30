from jocky.research.lab import build_scenario, analyze, run


def test_lab_scenario_is_synthetic_and_detectable():
    evidence = build_scenario()
    assert evidence["lab_only"] is True
    findings = analyze(evidence)
    names = {f["rule_name"] for f in findings}
    assert "in_memory_execution_indicators" in names
    assert "byovd_driver_indicators" in names


def test_clean_scenario_has_no_research_findings():
    evidence = build_scenario("clean")
    assert analyze(evidence) == []


def test_result_is_hashed():
    result = run("clean")
    assert len(result["result_sha256"]) == 64
