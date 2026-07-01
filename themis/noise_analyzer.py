import queue
import threading
import traceback

from .llm import get_answer
from .logs import parse_text2json
from .prompts import generate_noise_analysis_prompt
from . import rules


class NoiseAnalyzer:

    def __init__(self, rules_path, queue_maxsize=64):
        self.rules_path = rules_path
        self._q = queue.Queue(maxsize=queue_maxsize)
        self._stop = threading.Event()
        self._thread = None
        self._learned = 0
        self._tokens = 0

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="themis-noise-analyzer", daemon=True)
        self._thread.start()

    def submit(self, chunk, detected_entities):
        try:
            self._q.put_nowait((list(chunk), list(detected_entities)))
        except queue.Full:
            pass

    def stop(self):
        self._stop.set()

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)

    @property
    def learned(self):
        return self._learned

    @property
    def tokens(self):
        return self._tokens

    def _run(self):
        while not self._stop.is_set() or not self._q.empty():
            try:
                chunk, detected = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._analyze(chunk, detected)
            except Exception as e:
                print(f"[noise_analyzer] error (ignored): {e}")
                traceback.print_exc()

    def _analyze(self, chunk, detected):
        if not chunk:
            return
        chunk_text = "\n".join(chunk)
        prompt = generate_noise_analysis_prompt(chunk_text, detected)
        try:
            _reasoning, answer, stats = get_answer(prompt)
        except Exception as e:
            print(f"[noise_analyzer] LLM call failed (ignored): {e}")
            return
        self._tokens += stats.get("tokens", {}).get("total", 0)
        try:
            result = parse_text2json(answer)
        except Exception:
            print("[noise_analyzer] non-JSON answer (ignored)")
            return
        patterns = result.get("noise_patterns", []) if isinstance(result, dict) else []
        patterns = [p for p in patterns if isinstance(p, dict) and p.get("regex")]
        added = rules.add_patterns(self.rules_path, patterns, source="analyzer")
        if added:
            self._learned += added
            print(f"[noise_analyzer] learned {added} pattern(s) (total {self._learned}) -> {self.rules_path}")
