"""Stage exact canonical public documents into build output, never the checkout."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from setuptools.command.build_py import build_py

# Setuptools loads cmdclass by file spec, without adding the checkout to
# sys.path. Load only the anchored stdlib-only map, never an installed agora.
_RESOURCE_SPEC = spec_from_file_location(
    "_sab_build_resource_map", Path(__file__).resolve().parent / "agora" / "public_resources.py"
)
if _RESOURCE_SPEC is None or _RESOURCE_SPEC.loader is None:
    raise RuntimeError("The canonical public resource map is unavailable.")
_RESOURCE_MODULE = module_from_spec(_RESOURCE_SPEC)
_RESOURCE_SPEC.loader.exec_module(_RESOURCE_MODULE)
STAGED_RESOURCES = _RESOURCE_MODULE.STAGED_RESOURCES


class BuildPy(build_py):
    def _resource_mapping(self):
        return {
            str(Path(self.build_lib, "agora", "_public_resources", *destination)): str(
                Path(*source)
            )
            for destination, source in STAGED_RESOURCES.items()
        }

    def run(self):
        super().run()
        if getattr(self, "editable_mode", False):
            return
        root = Path(__file__).resolve().parent
        for destination, relative_source in self._resource_mapping().items():
            source = root / relative_source
            if not source.is_file() or not source.resolve().is_relative_to(root):
                raise FileNotFoundError(f"Canonical public resource is missing: {relative_source}")
            target = Path(destination)
            self.mkpath(str(target.parent))
            if not self.dry_run:
                target.write_bytes(source.read_bytes())

    def get_source_files(self):
        return super().get_source_files() + [
            str(Path(*source)) for source in STAGED_RESOURCES.values()
        ]

    def get_outputs(self, include_bytecode=1):
        return super().get_outputs(include_bytecode) + list(self._resource_mapping())

    def get_output_mapping(self):
        inherited = getattr(super(), "get_output_mapping", lambda: {})()
        return {**inherited, **self._resource_mapping()}
