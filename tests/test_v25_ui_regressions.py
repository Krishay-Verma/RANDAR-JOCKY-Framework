from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_domain_expansion_template_includes_memory_and_driver_collection():
    source = (ROOT / "frontend" / "src" / "lib.js").read_text()
    start = source.index('"Domain Expansion Triage"')
    block = source[start:source.index('"V1.5 DSL Showcase"', start)]
    assert "collect memory_regions;" in block
    assert "collect driver_inventory;" in block
    assert "analyze in_memory_execution_indicators;" in block
    assert "analyze byovd_driver_indicators;" in block
    assert "analyze driver_forensics_exposure;" in block
    assert "analyze persistence_cross_surface_correlation;" in block
    assert "analyze persistence_privilege_correlation;" in block


def test_engine_reference_has_dedicated_wrapping_classes():
    source = (ROOT / "frontend" / "src" / "pages" / "NewInvestigation.jsx").read_text()
    assert 'className="engine-reference-scroll"' in source
    assert 'className="ref-item"' in source


def test_investigation_detail_exposes_memory_and_driver_tabs():
    source = (ROOT / "frontend" / "src" / "pages" / "InvestigationDetail.jsx").read_text()
    assert '["memory", `Memory Forensics' in source
    assert '["driver", `Driver Forensics' in source
    assert 'const MEMORY_RULES' in source
    assert 'const DRIVER_RULES' in source


def test_investigation_list_exposes_memory_and_driver_columns():
    source = (ROOT / "frontend" / "src" / "pages" / "Investigations.jsx").read_text()
    assert '<th>Memory</th><th>Drivers</th>' in source
    assert 'function specializedForensics' in source


def test_investigation_detail_exposes_persistence_tab():
    source = (ROOT / "frontend" / "src" / "pages" / "InvestigationDetail.jsx").read_text()
    assert 'tab === "persistence"' in source
    assert 'persistenceForensicsEvidence' in source


def test_investigation_list_uses_row_scope_for_forensics_record_counts():
    source = (ROOT / "frontend" / "src" / "pages" / "Investigations.jsx").read_text()
    assert 'record?.memory_forensics_records' not in source
    assert 'record?.driver_forensics_records' not in source
    assert 'r?.memory_forensics_records' in source
    assert 'r?.driver_forensics_records' in source


def test_persistence_workspace_is_routed_and_api_is_exposed():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    client = (ROOT / "frontend" / "src" / "api" / "client.js").read_text()
    assert '/persistence-forensics' in app
    assert 'persistenceForensicsScan' in client


def test_v27_investigation_forensics_have_direct_pivots_and_wrapped_tabs():
    detail = (ROOT / "frontend" / "src" / "pages" / "InvestigationDetail.jsx").read_text()
    css = (ROOT / "frontend" / "src" / "index.css").read_text()
    investigations = (ROOT / "frontend" / "src" / "pages" / "Investigations.jsx").read_text()
    assert 'useSearchParams' in detail
    assert '?tab=memory' in investigations
    assert '?tab=driver' in investigations
    assert 'specialized-tabs' in detail
    assert 'Cross-Surface Correlation' in detail
    assert '.detail-tabs{display:flex;flex-wrap:wrap' in css
    assert '.forensics-list-links' in css
