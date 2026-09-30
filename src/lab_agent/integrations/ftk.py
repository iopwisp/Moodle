"""AccessData / Exterro FTK Imager integration.

The GUI is driven only through its profile (launch + window evidence).  The
verifiable part is the acquisition log FTK Imager writes next to an image
(``<image>.txt``): the MD5/SHA-1 values it reports are compared with hashes
computed independently from the image bytes.
"""

from __future__ import annotations

import re
from typing import Any

from ..workspace import calculate_hashes
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_str,
)

FTK_SPEC = AppSpec("ftk", "FTK Imager", env_var="LAB_AGENT_FTK_PATH", executables=("FTK Imager.exe", "FTKImager.exe"),
                   install_globs=("AccessData/FTK Imager/FTK Imager.exe", "Exterro/FTK Imager/FTK Imager.exe"),
                   registry_name_re=r"FTK Imager", capabilities=("ftk.*",))


class FTKAdapter(BaseIntegration):
    name = "ftk"
    APPLICATIONS = (FTK_SPEC,)
    CAPABILITIES = (
        Capability("ftk.launch", "ftk", "Start FTK Imager and capture its window", (), ("screenshot",), "window visible",
                   requires=("app:ftk",), keywords=("ftk imager", "ftk")),
        Capability("ftk.verify_acquisition_log", "ftk", "Compare hashes in an FTK Imager acquisition log with the image",
                   (Param("log", "path", True, "FTK Imager .txt log"), Param("image", "path", True)), ("hash",),
                   "MD5/SHA-1 in the log equal the recomputed values", keywords=("acquisition", "e01")),
        Capability("ftk.capture_evidence", "ftk", "Screenshot of the FTK Imager window", (), ("screenshot",),
                   "valid window screenshot", requires=("app:ftk",)),
    )

    def _app(self, context: ExecutionContext) -> Any:
        from ..applications import ManagedApplication

        return ManagedApplication("ftk", context, spec=FTK_SPEC)

    def launch(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        app.launch()
        picture = app.screenshot(f"ftk_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "FTK Imager window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def capture_evidence(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        app = self._app(context)
        if app.running_window() is None:
            return IntegrationResult.failed("FTK Imager is not open.")
        picture = app.screenshot(f"ftk_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "FTK Imager window", "screenshot")])

    def verify_acquisition_log(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        log_text = context.resolve(param_str(parameters, "log"), base="input").read_text(encoding="utf-8", errors="replace")
        image = context.resolve(param_str(parameters, "image"), base="input")
        reported = {
            "md5": next(iter(re.findall(r"MD5 checksum:\s*([0-9a-fA-F]{32})", log_text)), None),
            "sha1": next(iter(re.findall(r"SHA1 checksum:\s*([0-9a-fA-F]{40})", log_text)), None),
        }
        if not any(reported.values()):
            return IntegrationResult.failed("The log contains no MD5/SHA1 checksum lines.")
        actual = calculate_hashes(image)
        comparison = {name: (value.lower() == actual[name]) for name, value in reported.items() if value}
        ok = all(comparison.values())
        output = context.save_result(f"ftk_log_verification_{image.name}.txt",
                                     "\n".join(f"{k}: log={reported[k]} computed={actual[k]} match={v}" for k, v in comparison.items()))
        return IntegrationResult(ok, {"comparison": comparison, **({} if ok else {"reason": "hash in log differs from image"})},
                                 [evidence(output, "FTK acquisition log verification", "hash")])


def create_adapters(services: Any) -> list[FTKAdapter]:
    return [FTKAdapter()]
