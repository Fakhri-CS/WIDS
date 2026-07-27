from __future__ import annotations

import unittest

from wids.capture.channel_manager import (
    ChannelManager,
    channel_to_frequency,
    frequency_to_channel,
)
from wids.capture.interface_manager import (
    CommandResult,
    InterfaceManager,
)


class StatefulRunner:
    def __init__(self) -> None:
        self.mode = "managed"
        self.up = True
        self.calls: list[tuple[str, ...]] = []

    def run(self, args, *, check: bool = True) -> CommandResult:
        del check
        command = tuple(args)
        self.calls.append(command)
        if command == ("iw", "dev"):
            output = (
                "phy#0\n"
                "\tInterface wlan0\n"
                "\t\taddr aa:bb:cc:dd:ee:ff\n"
                f"\t\ttype {self.mode}\n"
                "\t\tchannel 6 (2437 MHz), width: 20 MHz\n"
            )
            return CommandResult(command, 0, output, "")
        if command[:5] == ("iw", "dev", "wlan0", "set", "type"):
            self.mode = command[-1]
        if command == ("ip", "link", "set", "dev", "wlan0", "down"):
            self.up = False
        if command == ("ip", "link", "set", "dev", "wlan0", "up"):
            self.up = True
        if command == ("ip", "-o", "link", "show", "dev", "wlan0"):
            flags = "<BROADCAST,MULTICAST,UP>" if self.up else "<BROADCAST>"
            return CommandResult(command, 0, f"3: wlan0: {flags}", "")
        if command == ("iw", "dev", "wlan0", "info"):
            return CommandResult(command, 0, "channel 11 (2462 MHz)", "")
        return CommandResult(command, 0, "", "")


class InterfaceAndChannelTests(unittest.TestCase):
    def test_interface_manager_enables_and_verifies_monitor_mode(self) -> None:
        runner = StatefulRunner()
        manager = InterfaceManager(runner)

        interface = manager.ensure_monitor_mode("wlan0")

        self.assertTrue(interface.monitor_mode)
        self.assertTrue(interface.is_up)
        self.assertIn(
            ("iw", "dev", "wlan0", "set", "type", "monitor"),
            runner.calls,
        )

    def test_channel_manager_uses_argument_vector_without_shell(self) -> None:
        runner = StatefulRunner()
        manager = ChannelManager("wlan0", runner)

        manager.set_channel(6, "HT20")

        self.assertIn(
            ("iw", "dev", "wlan0", "set", "channel", "6", "HT20"),
            runner.calls,
        )
        self.assertEqual(manager.current_channel(), 11)

    def test_frequency_channel_conversion_covers_supported_bands(self) -> None:
        self.assertEqual(frequency_to_channel(2437), 6)
        self.assertEqual(frequency_to_channel(2484), 14)
        self.assertEqual(frequency_to_channel(5180), 36)
        self.assertEqual(frequency_to_channel(5955), 1)
        self.assertEqual(frequency_to_channel(7115), 233)
        self.assertIsNone(frequency_to_channel(2400))
        self.assertEqual(channel_to_frequency(6), 2437)
        self.assertEqual(channel_to_frequency(36), 5180)
        self.assertEqual(channel_to_frequency(5, band="6"), 5975)


if __name__ == "__main__":
    unittest.main()
