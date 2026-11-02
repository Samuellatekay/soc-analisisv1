import threading

from app.main import _start_policy_agent


def test_policy_agent_can_run_with_separate_queue_workers(monkeypatch):
    from services.engine import policy_agent

    marker = object()
    started = []

    class Thread:
        def __init__(self, *, target, args, daemon, name):
            self.values = (target, args, daemon, name)

        def start(self):
            started.append(self.values)

    monkeypatch.setattr(policy_agent.PolicyAgent, "from_env", classmethod(lambda cls: marker))
    monkeypatch.setattr(threading, "Thread", Thread)
    monkeypatch.setenv("MASTER_URL", "https://master.example")
    monkeypatch.setenv("MASTER_POLICY_AGENT_ENABLED", "1")

    _start_policy_agent(threading.Event())

    assert len(started) == 1
    target, args, daemon, name = started[0]
    assert target is policy_agent.loop
    assert args[0] is marker
    assert args[1] == 60
    assert isinstance(args[2], threading.Event)
    assert daemon is True
    assert name == "policy-agent"


def test_policy_agent_can_be_disabled_for_dedicated_deployment(monkeypatch):
    monkeypatch.setenv("MASTER_URL", "https://master.example")
    monkeypatch.setenv("MASTER_POLICY_AGENT_ENABLED", "false")

    _start_policy_agent(threading.Event())
