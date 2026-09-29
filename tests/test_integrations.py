from pathlib import Path

from lab_agent.integrations.base import ExecutionContext, IntegrationResult
from lab_agent.integrations.registry import IntegrationRegistry, build_registry


def test_builtin_capabilities_are_discoverable() -> None:
    registry = build_registry()
    names = {capability.name for capability in registry.capabilities()}

    assert "core.hash_inputs" in names
    assert "browser.visit" in names
    assert "desktop.profile" in names
    assert "autopsy.e2e" in names


def test_legacy_action_names_are_normalized() -> None:
    registry = build_registry()

    assert registry.normalize("autopsy_e2e") == "autopsy.e2e"
    assert registry.normalize("browser") == "browser.visit"
    assert registry.has("desktop")


def test_third_party_adapter_can_register_without_runner_changes(tmp_path: Path) -> None:
    class PacketTracerAdapter:
        name = "packet_tracer"

        def capabilities(self):
            from lab_agent.integrations.base import Capability
            return [
                Capability(
                    name="packet_tracer.verify_connectivity",
                    tool="packet_tracer",
                    description="Verify a simulated topology",
                    parameters=("project",),
                    evidence_types=("screenshot",),
                )
            ]

        def execute(self, capability, parameters, context):
            assert capability == "packet_tracer.verify_connectivity"
            assert parameters["project"] == "lab.pkt"
            return IntegrationResult(
                verified=True,
                details={"project": parameters["project"]},
                evidence=[],
            )

    registry = IntegrationRegistry()
    registry.register(PacketTracerAdapter())
    result = registry.execute(
        "packet_tracer.verify_connectivity",
        {"project": "lab.pkt"},
        ExecutionContext(tmp_path, "Assignment_1"),
    )

    assert result.verified
