from io import StringIO
import unittest

from cli_progress import ProgressIndicator


class ProgressIndicatorTests(unittest.TestCase):
    def test_non_interactive_output_keeps_only_forced_and_final_updates(self):
        stream = StringIO()
        progress = ProgressIndicator(
            "Port scan",
            100,
            unit="ports",
            stream=stream,
            interactive=False,
        )

        progress.update(1, "192.168.2.10")
        progress.update(50, "192.168.2.10")
        self.assertEqual(stream.getvalue(), "")

        progress.finish("completed in 1.2s")

        output = stream.getvalue()
        self.assertIn("Port scan [██████████████████]", output)
        self.assertIn("100% · 100/100 ports", output)
        self.assertIn("completed in 1.2s", output)
        self.assertEqual(output.count("\n"), 1)

    def test_interactive_output_updates_one_terminal_line(self):
        stream = StringIO()
        progress = ProgressIndicator(
            "ARP scan",
            4,
            unit="steps",
            stream=stream,
            interactive=True,
            min_interval=0,
        )

        progress.update(1, "discovering")
        progress.finish("completed")

        output = stream.getvalue()
        self.assertIn("\rARP scan [", output)
        self.assertIn("25% · 1/4 steps · discovering", output)
        self.assertIn("100% · 4/4 steps · completed", output)
        self.assertTrue(output.endswith("\n"))

    def test_failure_keeps_current_position_and_terminates_line(self):
        stream = StringIO()
        progress = ProgressIndicator(
            "Network health",
            5,
            unit="steps",
            stream=stream,
            interactive=True,
            min_interval=0,
        )

        progress.update(2, "gateway reachability")
        progress.fail()

        output = stream.getvalue()
        self.assertIn("40% · 2/5 steps · failed", output)
        self.assertTrue(output.endswith("\n"))
        self.assertTrue(progress.finished)


if __name__ == "__main__":
    unittest.main()
