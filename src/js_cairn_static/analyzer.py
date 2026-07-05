from __future__ import annotations

from time import perf_counter
from typing import Callable

from .cluster import APIClusterer
from .collector import JSCollector
from .dataflow import DataflowAnalyzer
from .exposures import collect_exposures
from .extractors import CallGraphExtractor, ExtractionContext, ProbeResult, RequestExtractor, WrapperDetector
from .fingerprints import collect_fingerprints
from .models import AssetAnalysisTrace, AssetKind, CallGraphEdge, Location, StaticAnalysisReport
from .parser import JSParser
from .risk import RiskSemanticTagger

LARGE_FILE_THRESHOLD_BYTES = 5 * 1024 * 1024


class StaticAnalyzer:
    def __init__(
        self,
        *,
        verify_ssl: bool = True,
        progress: Callable[[str], None] | None = None,
        show_browser: bool = False,
        browser_timeout_ms: int = 30000,
        pause_on_browser_fail: bool = False,
        max_remote_assets: int = 48,
    ) -> None:
        self.progress = progress
        self.collector = JSCollector(
            verify_ssl=verify_ssl,
            progress=progress,
            show_browser=show_browser,
            browser_timeout_ms=browser_timeout_ms,
            pause_on_browser_fail=pause_on_browser_fail,
            max_remote_assets=max_remote_assets,
        )
        self.parser = JSParser()
        self.wrapper_detector = WrapperDetector()
        self.request_extractor = RequestExtractor()
        self.call_graph = CallGraphExtractor()
        self.dataflow = DataflowAnalyzer()
        self.risk = RiskSemanticTagger()
        self.clusterer = APIClusterer()

    def analyze(self, target: str) -> StaticAnalysisReport:
        self._emit(f"starting analysis: {target}")
        report = StaticAnalysisReport(target=target)
        report.assets = self.collector.collect(target)
        report.exposures = collect_exposures(report.assets)
        report.fingerprints = collect_fingerprints(report.assets)
        self._emit(f"collection complete: {len(report.assets)} assets")
        all_wrappers = []
        contexts: list[tuple[ExtractionContext, object, ProbeResult, str, int]] = []

        analyzable_assets = sorted(
            [asset for asset in report.assets if asset.kind != AssetKind.html],
            key=asset_priority,
            reverse=True,
        )
        self._emit(f"parsing assets: {len(analyzable_assets)}")
        for index, asset in enumerate(analyzable_assets, start=1):
            file_ref = asset.path or asset.url or asset.asset_id
            large_file = is_large_file_asset(asset)
            priority = asset_priority(asset)
            self._emit(
                f"parsing asset {index}/{len(analyzable_assets)}: {file_ref} "
                f"(size={format_bytes(asset.size)}, minified={asset.minified}, "
                f"source_map={bool(asset.source_map_url)}, large_strategy={large_file}, priority={priority})"
            )
            context_start = perf_counter()
            self._emit(f"  context build start: {file_ref}")
            ctx = ExtractionContext(
                asset.normalized_code or asset.raw_code,
                file_ref=file_ref,
                progress=self.progress,
                learn_constants=not large_file,
            )
            context_elapsed = perf_counter() - context_start
            self._emit(
                f"  context build done: strings={len(ctx.constants.values)}, "
                f"objects={len(ctx.constants.object_values)}, elapsed={context_elapsed:.2f}s"
            )
            probe = self.request_extractor.probe(ctx.code)
            strategy, skipped_reason = choose_asset_strategy(asset, probe)
            self._emit(f"  extraction strategy: {strategy} ({probe.summary()})")
            report.asset_traces.append(
                AssetAnalysisTrace(
                    asset_ref=file_ref,
                    priority=priority,
                    strategy=strategy,
                    quick_hits=probe.quick_hits,
                    candidate_endpoints=probe.candidate_endpoints[:10],
                    skipped_reason=skipped_reason,
                )
            )
            contexts.append((ctx, asset, probe, strategy, priority))
            if strategy in {"skip", "light"} and large_file:
                self._emit(
                    f"  large file strategy enabled: threshold={format_bytes(LARGE_FILE_THRESHOLD_BYTES)}; "
                    "skipping constant learning, AST parsing, wrapper scan, dataflow, and call graph"
                )
            if strategy in {"skip", "light"}:
                if skipped_reason:
                    report.diagnostics.append(f"{file_ref}: {skipped_reason}")
            if strategy != "full":
                continue
            parse_start = perf_counter()
            self._emit(f"  AST parse start: {file_ref}")
            parse = self.parser.parse(ctx.code)
            parse_elapsed = perf_counter() - parse_start
            parser_label = parse.parser
            if parse.error:
                report.diagnostics.append(f"{file_ref}: parser fallback after {parse.error}")
                parser_label = f"{parse.parser} fallback"
            self._emit(f"  AST parse done: parser={parser_label}, elapsed={parse_elapsed:.2f}s")

            wrapper_start = perf_counter()
            self._emit(f"  wrapper scan start: {file_ref}")
            wrappers = self.wrapper_detector.detect(ctx)
            wrapper_elapsed = perf_counter() - wrapper_start
            all_wrappers.extend(wrappers)
            self._emit(f"  wrapper scan done: found={len(wrappers)}, elapsed={wrapper_elapsed:.2f}s")

        report.wrappers = dedupe_wrappers(all_wrappers)
        self._emit(f"wrapper detection complete: {len(report.wrappers)} wrappers")

        self._emit(f"extracting requests from {len(contexts)} assets")
        for index, (ctx, asset, probe, strategy, priority) in enumerate(contexts, start=1):
            self._emit(f"extracting asset {index}/{len(contexts)}: {ctx.file_ref}")
            if strategy == "skip":
                continue
            if strategy == "light":
                self._emit("  request extraction mode: light strategy")
            apis = self.request_extractor.extract(ctx, [] if strategy != "full" else report.wrappers, mode=strategy)
            if strategy == "full":
                self.dataflow.analyze(ctx.code, apis)
            report.apis.extend(apis)
            update_trace(report.asset_traces, ctx.file_ref, len(apis))
            add_backtrace_diagnostics(report, ctx.file_ref, probe, apis, strategy)
            if strategy != "full":
                continue
            for caller, callee, offset in self.call_graph.extract(ctx):
                line, column = line_col(ctx.code, offset)
                report.call_graph.append(CallGraphEdge(caller=caller, callee=callee, location=Location(file=ctx.file_ref, line=line, column=column)))

        report.apis = dedupe_apis(report.apis)
        self._emit(f"deduplicated APIs: {len(report.apis)}")
        self._emit("tagging and clustering APIs")
        self.risk.tag(report.apis)
        report.apis.sort(key=lambda api: api.priority, reverse=True)
        report.clusters = self.clusterer.cluster(report.apis)
        self._emit(
            f"analysis complete: {len(report.apis)} apis, {len(report.clusters)} clusters, "
            f"{len(report.exposures)} exposures, {len(report.fingerprints)} fingerprints"
        )
        return report

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)


def dedupe_wrappers(wrappers):
    by_name = {}
    for wrapper in wrappers:
        existing = by_name.get(wrapper.name)
        if not existing or wrapper.confidence > existing.confidence:
            by_name[wrapper.name] = wrapper
    return sorted(by_name.values(), key=lambda item: item.confidence, reverse=True)


def dedupe_apis(apis):
    merged = {}
    for api in apis:
        key = (api.method, api.url_template)
        if key not in merged:
            merged[key] = api
            continue
        existing = merged[key]
        existing.params = {f"{p.location.value}:{p.name}": p for p in existing.params + api.params}.values()
        existing.params = list(existing.params)
        existing.headers = sorted(set(existing.headers + api.headers))
        existing.transforms = sorted(set(existing.transforms + api.transforms))
        existing.evidence.extend(api.evidence)
        existing.risk_tags = sorted(set(existing.risk_tags + api.risk_tags))
        existing.confidence = max(existing.confidence, api.confidence)
    return list(merged.values())


def line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last = text.rfind("\n", 0, offset)
    return line, offset + 1 if last < 0 else offset - last


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def is_large_file_asset(asset) -> bool:
    return asset.size >= LARGE_FILE_THRESHOLD_BYTES


def is_large_file_text(code: str) -> bool:
    return len(code) >= LARGE_FILE_THRESHOLD_BYTES


def asset_priority(asset) -> int:
    score = asset.fetch_priority
    if not asset.third_party:
        score += 40
    if is_large_file_asset(asset):
        score -= 20
    return score


def choose_asset_strategy(asset, probe: ProbeResult) -> tuple[str, str | None]:
    if is_large_file_asset(asset):
        return "light", "large file strategy enabled"
    if asset.third_party and probe.signal_score == 0:
        return "skip", "third-party asset with no request signals"
    if asset.third_party and probe.signal_score <= 2:
        return "light", "third-party asset with weak request signals"
    if probe.signal_score == 0 and asset_priority(asset) < 20:
        return "skip", "low-priority asset with no request signals"
    if probe.signal_score <= 1 and asset_priority(asset) < 40:
        return "light", "low-signal asset using light extraction"
    return "full", None


def update_trace(traces: list[AssetAnalysisTrace], asset_ref: str, extracted_api_count: int) -> None:
    for trace in traces:
        if trace.asset_ref == asset_ref:
            trace.extracted_api_count = extracted_api_count
            return


def add_backtrace_diagnostics(report: StaticAnalysisReport, asset_ref: str, probe: ProbeResult, apis, strategy: str) -> None:
    if apis:
        return
    if probe.candidate_endpoints and probe.signal_score:
        report.diagnostics.append(
            f"{asset_ref}: request-like signals present but no API extracted "
            f"({probe.summary()}); candidate endpoints={', '.join(probe.candidate_endpoints[:5])}"
        )
        return
    if probe.candidate_endpoints and strategy != "full":
        report.diagnostics.append(
            f"{asset_ref}: endpoint hints observed under {strategy} strategy; candidate endpoints="
            f"{', '.join(probe.candidate_endpoints[:5])}"
        )
