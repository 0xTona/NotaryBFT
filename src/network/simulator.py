"""Deterministic discrete-event network simulator."""

import heapq
from typing import Callable, Dict, List, Optional, Tuple


class Simulator:
    """
    Virtual-clock discrete-event simulator.
    Events are scheduled and executed in strictly deterministic order.
    """

    def __init__(self, seed: int = 42):
        self.virtual_time: float = 0.0
        # Priority queue entries: (timestamp, sequence_num, callback, is_cancelled)
        self._event_queue: List[Tuple[float, int, Callable[[], None], List[bool]]] = []
        self._seq: int = 0
        self._active_timers: Dict[int, List[bool]] = {}
        self._timer_counter: int = 0
        self.seed = seed

    def now(self) -> float:
        return self.virtual_time

    def schedule_event(self, delay: float, callback: Callable[[], None]) -> int:
        """Schedules a callback to be called at virtual_time + delay."""
        assert delay >= 0, "Delay must be non-negative"
        scheduled_time = self.virtual_time + delay
        self._seq += 1
        self._timer_counter += 1
        timer_id = self._timer_counter
        cancel_box = [False]  # mutable flag
        self._active_timers[timer_id] = cancel_box
        heapq.heappush(self._event_queue, (scheduled_time, self._seq, callback, cancel_box))
        return timer_id

    def cancel_event(self, timer_id: int) -> None:
        """Cancels a scheduled event by its timer_id."""
        if timer_id in self._active_timers:
            self._active_timers[timer_id][0] = True
            del self._active_timers[timer_id]

    def step(self) -> bool:
        """Executes the next event. Returns True if an event was executed, False if queue is empty."""
        while self._event_queue:
            t, _, cb, cancel_box = heapq.heappop(self._event_queue)
            if cancel_box[0]:
                continue  # cancelled
            self.virtual_time = t
            cb()
            return True
        return False

    def run_until(self, max_time: float) -> None:
        """Runs the simulator until max_time is reached or no events remain."""
        while self._event_queue:
            if self._event_queue[0][0] > max_time:
                self.virtual_time = max_time
                break
            self.step()

    def run_until_condition(self, condition: Callable[[], bool], max_time: float) -> bool:
        """Runs simulator until condition() evaluates to True or max_time is exceeded."""
        while self._event_queue and self.virtual_time <= max_time:
            if condition():
                return True
            if self._event_queue[0][0] > max_time:
                self.virtual_time = max_time
                break
            self.step()
        return condition()
