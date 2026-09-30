from jocky.analysis.research_rules import (
    rule_byoVD_driver_indicators,
    rule_in_memory_execution_indicators,
)


def test_in_memory_correlation_is_observation_only():
    evidence = {
        "processes": {"processes": [{"pid": 42, "name": "lab.exe"}]},
        "memory_regions": {"regions": [{
            "pid": 42, "base_address": 0x1000, "region_size": 0x2000,
            "is_private_executable": True,
        }]},
        "threads": {"threads": [{
            "pid": 42, "process_name": "lab.exe", "thread_id": 7,
            "start_address": 0x1800,
        }]},
        "modules": {"modules": [{
            "pid": 42, "is_user_writable": True,
        }]},
    }
    findings = rule_in_memory_execution_indicators(evidence)
    assert len(findings) == 1
    assert findings[0].rule_name == "in_memory_execution_indicators"
    assert findings[0].related_evidence["indicators"] == [
        "private_executable_memory",
        "thread_start_in_private_executable_memory",
        "user_writable_loaded_module",
    ]


def test_byovd_rule_uses_supplied_catalog_result():
    evidence = {"driver_inventory": {"drivers": [{
        "service_name": "LabDriver",
        "display_name": "Lab Driver",
        "image_path": r"C:\\Windows\\System32\\drivers\\lab.sys",
        "known_vulnerable": True,
        "vulnerability_ids": ["LOCAL-LAB-001"],
        "file_exists": True,
        "is_user_writable_path": False,
        "sha256": "abc",
    }]}}
    findings = rule_byoVD_driver_indicators(evidence)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].related_evidence["vulnerability_ids"] == ["LOCAL-LAB-001"]


def test_byovd_rule_ignores_clean_driver():
    evidence = {"driver_inventory": {"drivers": [{
        "service_name": "CleanDriver",
        "known_vulnerable": False,
        "file_exists": True,
        "is_user_writable_path": False,
    }]}}
    assert rule_byoVD_driver_indicators(evidence) == []
