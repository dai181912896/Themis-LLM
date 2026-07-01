"""Runtime parallel noise analyzer (Stage 2 optimization).

An opt-in background thread that runs alongside ``neighbor_scan``. For each raw
chunk the main loop submits, the analyzer asks the LLM (its own ``get_answer``
call, genuinely concurrent with the main loop's calls) which lines are redundant
normal noise, generalizes them into object-path regexes, and persists them to
``rules.json`` via ``themis.rules.add_patterns``. The main loop re-reads
``rules.json`` each batch, so patterns learned early help later batches — a
real-time feedback loop that also persists across runs.

Thread-safety: the analyzer is the only writer to ``rules.json`` (locked +
atomic in ``rules.py``); the main loop only reads. The shared OpenAI client
(``themis.llm._client``) is concurrency-safe (httpx pool).

Analyzer failures are ALWAYS swallowed (logged + continue) — a background LLM
error must never crash the main investigation.
"""
import queue
import threading
import traceback

from .llm import get_answer
from .logs import parse_text2json
from .prompts import generate_noise_analysis_prompt
from . import rules


class NoiseAnalyzer:
    """Consume raw chunks on a worker thread; learn noise patterns into rules.json."""

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
        """Non-blocking enqueue of a raw chunk for analysis. Drops if full."""
        try:
            self._q.put_nowait((list(chunk), list(detected_entities)))
        except queue.Full:
            pass  # back-pressure: main loop proceeds regardless

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
                # NEVER propagate — background failures are non-fatal.
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
        # Sanity-filter: require a non-empty regex string.
        patterns = [p for p in patterns if isinstance(p, dict) and p.get("regex")]
        added = rules.add_patterns(self.rules_path, patterns, source="analyzer")
        if added:
            self._learned += added
            print(f"[noise_analyzer] learned {added} pattern(s) (total {self._learned}) -> {self.rules_path}")
