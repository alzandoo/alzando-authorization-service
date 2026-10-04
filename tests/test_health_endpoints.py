from alzando_authorization import main as main_module


def test_health_endpoints_report_service_readiness(api, monkeypatch):
    client, sessions, _ = api
    monkeypatch.setattr(main_module, "engine", sessions.kw["bind"])
    live = client.get("/health/live")
    ready = client.get("/health/ready")
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok"}
