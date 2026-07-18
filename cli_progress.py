"""Shared terminal progress rendering for the command-line scanners."""

import sys
import time


DEFAULT_BAR_WIDTH = 18


class ProgressIndicator:
    """Render one compact determinate progress line on stderr.

    Interactive terminals receive throttled in-place updates. Redirected output
    receives only the final line so logs and machine-readable stdout stay clean.
    """

    def __init__(
        self,
        label,
        total,
        *,
        unit="",
        stream=None,
        bar_width=DEFAULT_BAR_WIDTH,
        min_interval=0.08,
        interactive=None,
    ):
        self.label = label
        self.total = max(int(total), 1)
        self.unit = unit
        self.stream = stream or sys.stderr
        self.bar_width = bar_width
        self.min_interval = min_interval
        self.interactive = (
            bool(getattr(self.stream, "isatty", lambda: False)())
            if interactive is None
            else interactive
        )
        self.current = 0
        self.started_at = time.monotonic()
        self.last_rendered_at = 0.0
        self.last_rendered_width = 0
        self.finished = False

    def _write_line(self, line, *, terminate=False):
        """Render a line and erase any tail left by a longer previous update."""
        if self.interactive:
            padding = " " * max(0, self.last_rendered_width - len(line))
            self.stream.write(f"\r{line}{padding}")
            if terminate:
                self.stream.write("\n")
            self.last_rendered_width = 0 if terminate else len(line)
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    def format_line(self, current=None, detail=None):
        current = self.current if current is None else current
        current = min(max(int(current), 0), self.total)
        ratio = current / self.total
        completed_width = round(ratio * self.bar_width)
        bar = "█" * completed_width + "░" * (self.bar_width - completed_width)
        count = f"{current}/{self.total}"
        if self.unit:
            count = f"{count} {self.unit}"
        suffix = f" · {detail}" if detail else ""
        return f"{self.label} [{bar}] {ratio:>4.0%} · {count}{suffix}"

    def update(self, current, detail=None, *, force=False):
        if self.finished:
            return
        self.current = min(max(int(current), 0), self.total)
        now = time.monotonic()
        should_render = force or self.current >= self.total
        if self.interactive and now - self.last_rendered_at >= self.min_interval:
            should_render = True
        if not should_render:
            return
        line = self.format_line(detail=detail)
        self._write_line(line)
        self.last_rendered_at = now

    def finish(self, detail=None):
        if self.finished:
            return
        elapsed = time.monotonic() - self.started_at
        final_detail = detail or f"completed in {elapsed:.1f}s"
        if self.interactive:
            self.current = self.total
            self._write_line(self.format_line(detail=final_detail), terminate=True)
        else:
            self.update(self.total, final_detail, force=True)
        self.finished = True

    def fail(self, detail="failed"):
        """Terminate the line at its current position after an exception."""
        if self.finished:
            return
        line = self.format_line(detail=detail)
        self._write_line(line, terminate=True)
        self.finished = True
