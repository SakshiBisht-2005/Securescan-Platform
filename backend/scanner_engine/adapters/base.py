"""Base interface every scanner adapter implements. The manager checks
`is_available()` before invoking `run()`, so adapters can assume the
underlying tool is present. `run()` must never raise for "the tool found
nothing" - only for genuine execution failure - and must always return a
list[NormalizedFinding] (possibly empty)."""
from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    name = "base"
    category_label = "sast"  # sast | sca | secrets | iac | container

    def is_available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def run(self, project_dir: str, exclusions: list) -> list:
        ...
