from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from schemas.flow_schema import FlowRecord


class WindowManager:
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds

        # Stores flows currently present in each host's active window.
        #
        # Example:
        # {
        #     "10.0.0.42": [flow1, flow2, flow3],
        #     "10.0.0.50": [flow4, flow5]
        # }
        self.active_windows: Dict[str, List[FlowRecord]] = {}

        # Stores the starting timestamp of each host's current window.
        #
        # Example:
        # {
        #     "10.0.0.42": datetime(...),
        #     "10.0.0.50": datetime(...)
        # }
        self.window_start_times: Dict[str, datetime] = {}

    def add_flow(self, flow: FlowRecord) -> List[Tuple[str, List[FlowRecord]]]:
        """
        Add one flow to the appropriate host window.

        Returns:
            A list of completed windows.

        Normally this list will contain either:
            []
        or:
            [(source_ip, completed_flows)]
        """

        source_ip = flow.src_ip

        # First flow seen from this host.
        if source_ip not in self.active_windows:
            self.active_windows[source_ip] = []
            self.window_start_times[source_ip] = flow.timestamp

        window_start = self.window_start_times[source_ip]

        elapsed_seconds = (
            flow.timestamp - window_start
        ).total_seconds()

        completed_windows = []

        # If the current flow belongs to a new time window,
        # close the previous window first.
        if elapsed_seconds >= self.window_seconds:

            completed_flows = self.active_windows[source_ip]

            if len(completed_flows) > 0:
                completed_windows.append(
                    (source_ip, completed_flows)
                )

            # Start a new window.
            self.active_windows[source_ip] = [flow]
            self.window_start_times[source_ip] = flow.timestamp

        else:
            # Flow still belongs to the current window.
            self.active_windows[source_ip].append(flow)

        return completed_windows

    def get_active_window(
        self,
        source_ip: str
    ) -> List[FlowRecord]:
        """
        Return the currently active window for a source host.
        """

        if source_ip not in self.active_windows:
            return []

        return self.active_windows[source_ip]

    def close_window(
        self,
        source_ip: str
    ) -> List[FlowRecord]:
        """
        Manually close the current window for a source host.

        Useful when shutting down the system or during testing.
        """

        if source_ip not in self.active_windows:
            return []

        completed_flows = self.active_windows[source_ip]

        self.active_windows[source_ip] = []

        if source_ip in self.window_start_times:
            del self.window_start_times[source_ip]

        return completed_flows

    def close_all_windows(
        self
    ) -> List[Tuple[str, List[FlowRecord]]]:
        """
        Close all currently active windows.

        Returns:
            List of (source_ip, flows) tuples.
        """

        completed_windows = []

        for source_ip in self.active_windows:

            flows = self.active_windows[source_ip]

            if len(flows) > 0:
                completed_windows.append(
                    (source_ip, flows)
                )

        self.active_windows.clear()
        self.window_start_times.clear()

        return completed_windows