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
        self.finished = False

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
        self.stream.write(("\r" if self.interactive else "") + line)
        if not self.interactive:
            self.stream.write("\n")
        self.stream.flush()
        self.last_rendered_at = now

    def finish(self, detail=None):
        if self.finished:
            return
        elapsed = time.monotonic() - self.started_at
        final_detail = detail or f"completed in {elapsed:.1f}s"
        self.update(self.total, final_detail, force=True)
        if self.interactive:
            self.stream.write("\n")
            self.stream.flush()
        self.finished = True

    def fail(self, detail="failed"):
        """Terminate the line at its current position after an exception."""
        if self.finished:
            return
        line = self.format_line(detail=detail)
        self.stream.write(("\r" if self.interactive else "") + line + "\n")
        self.stream.flush()
        self.finished = True
