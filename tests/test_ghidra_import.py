#!/usr/bin/env python3
"""Tests for tools/static/ghidra_import.py (task T-05, method S-02).

What is and is not tested here, and why
---------------------------------------
The thing this tool does -- run Ghidra over a 134 MB executable and time it --
is not testable in a test suite, and pretending otherwise would be worse than
admitting it. A single real stage takes minutes to hours, needs an 863 MB Ghidra
installation and a specific JDK, and its output is a *timing*, which has no
expected value. So no test here runs Ghidra, imports anything, or touches the
game installation.

What is tested is everything around that call, which is where the mistakes that
matter actually live:

* **argument handling** -- stage names and their canonical order, the ``all``
  expansion, an unknown stage, and the invocations that must be refused before
  anything is created;
* **the command line** -- that ``import-only`` really passes ``-noanalysis``,
  that the minimal stage really passes the pre-script and its analyzer list,
  that a soft analysis budget becomes ``-analysisTimeoutPerFile``, and that
  ``-deleteProject`` is never passed (it would delete the project whose size is
  half of the measurement);
* **the containment** -- that all four redirecting properties are produced, and
  that a path the batch launcher would mangle is refused with the character
  named rather than silently truncated into a different configuration;
* **the output-path guard** -- every path the tool can write (report, raw log,
  redacted log, project root, project deletion) refused inside an installation,
  plus the guard this tool adds and pathguard does not have: an *import* path
  inside an installation, which for Ghidra is a write because the importer opens
  its input read-write;
* **the copy discipline** -- that a digest mismatch aborts and that there is no
  way past it;
* **the report shape** -- driven through :func:`ghidra_import.run_stage` with an
  injected fake runner returning canned analyzeHeadless output, so the whole
  record is built, classified, serialised and summarised without Ghidra
  existing. This is the only reason the ``runner`` seam exists.
* **the C-13 refusal** -- a redactor that leaves a profile path behind must
  result in *no* file under ``research/evidence/``, because this repository is
  public and a partial redaction is a violation, not a warning.

The outcome classifier gets its own set of cases. "Timed out" is a *result* in
this tool, and the difference between the soft timeout (Ghidra stopped analysis
and saved a measurable project) and the hard one (we killed the process tree and
the database may be half-written) changes what the number means, so both are
asserted rather than lumped into "not completed".
"""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ghidra_import  # noqa: E402
import pathguard  # noqa: E402
from test_discovery import make_install_tree  # noqa: E402


# --------------------------------------------------------------------------- #
# canned analyzeHeadless output
# --------------------------------------------------------------------------- #

# Trimmed from a real capture of the control run (tbbmalloc.dll, default
# analyzer set). Real shape, real spacing, real message wording: the parser reads
# a third-party tool's console format, and a hand-idealised sample would test the
# parser against our idea of that format rather than against the format.
CANNED_DEFAULT_LOG = """\
INFO  Using log file: %APPDATA%\\ghidra\\ghidra_12.1.3_PUBLIC\\application.log (LoggingInitialization)
INFO  Headless startup complete (2241 ms) (AnalyzeHeadless)
INFO  Creating project: D:\\Tools\\ghidra-projects\\T05-control-default-analysis (DefaultProject)
INFO  IMPORTING: file:///D:/tools/ghidra-workspace/bin/tbbmalloc.dll (HeadlessAnalyzer)
WARN  Ignoring leading '_' chars on no-return name '___raise_securityfailure' (NoReturnFunctionAnalyzer)
INFO  ANALYZING all memory and code: file:///D:/tools/ghidra-workspace/bin/tbbmalloc.dll (HeadlessAnalyzer)
INFO  -----------------------------------------------------
    ASCII Strings                              0.205 secs
    Decompiler Parameter ID                    3.029 secs
    Windows x86 PE RTTI Analyzer               0.038 secs
-----------------------------------------------------
     Total Time   7 secs
-----------------------------------------------------
 (AutoAnalysisManager)
INFO  REPORT: Analysis succeeded for file: file:///D:/tools/ghidra-workspace/bin/tbbmalloc.dll (HeadlessAnalyzer)
INFO  REPORT: Save succeeded for: /tbbmalloc.dll (HeadlessAnalyzer)
INFO  REPORT: Import succeeded (HeadlessAnalyzer)
"""

CANNED_MINIMAL_LOG = """\
INFO  REPORT: Execute script: SetAnalyzerSet.java 'ASCII Strings;Reference'  (HeadlessAnalyzer)
INFO  SetAnalyzerSet.java> SETANALYZERSET: option_inventory_size=122 (GhidraScript)
INFO  SetAnalyzerSet.java> SETANALYZERSET: toggle_count=32 (GhidraScript)
INFO  SetAnalyzerSet.java> SETANALYZERSET: WARNING keep name is not an analyzer toggle: Create Function (GhidraScript)
INFO  SetAnalyzerSet.java> SETANALYZERSET: enabled=ASCII Strings (GhidraScript)
INFO  SetAnalyzerSet.java> SETANALYZERSET: enabled=Reference (GhidraScript)
INFO  SetAnalyzerSet.java> SETANALYZERSET: enabled_count=2 disabled_count=30 (GhidraScript)
INFO  REPORT: Analysis succeeded for file: file:///x (HeadlessAnalyzer)
INFO  REPORT: Import succeeded (HeadlessAnalyzer)
"""


class FakeRedactor:
    """Stands in for research/evidence/T-02/redact-log.py.

    Two behaviours are needed: one that redacts (so the committed-log path is
    exercised) and one that does not (so the refusal is exercised). The real
    redactor is loaded and asserted separately, once, below.
    """

    def __init__(self, *, actually_redact: bool = True) -> None:
        self.actually_redact = actually_redact

    def redact(self, text: str) -> str:
        if not self.actually_redact:
            return text
        return text.replace("C:\\Users\\somebody", "%USERPROFILE%")


def make_runner(output: str, *, exit_code: int = 0, timed_out: bool = False,
                seconds: float = 12.5, seen: list | None = None):
    """A fake ``run_process``: returns canned output without starting anything."""

    def runner(argv, env, timeout):
        if seen is not None:
            seen.append({"argv": list(argv), "timeout": timeout, "env": dict(env)})
        return {"exit_code": exit_code, "output": output,
                "wall_clock_seconds": seconds, "timed_out": timed_out,
                "kill_note": "taskkill /T /F exited 0" if timed_out else None}

    return runner


def make_target(tmp_path, *, role: str = "primary", size: int = 134658048) -> dict:
    """A target record shaped like :func:`ghidra_import.prepare_copy` returns."""
    copy = tmp_path / "bin" / "target.exe"
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_bytes(b"MZ" + b"\0" * 62)
    return {"role": role, "copy": str(copy), "bytes": size,
            "sha256": "0" * 64, "sha256_expected": "0" * 64,
            "sha256_matches": True, "source": str(copy),
            "reused_existing_copy": False, "copy_seconds": 0.0}


def make_project_on_disk(root, name: str, payload: bytes = b"x" * 4096) -> None:
    """A directory shaped like a saved Ghidra project, so sizes are measurable."""
    root = str(root)
    os.makedirs(os.path.join(root, name + ".rep", "idata"), exist_ok=True)
    with open(os.path.join(root, name + ".gpr"), "wb") as handle:
        handle.write(b"g" * 128)
    with open(os.path.join(root, name + ".rep", "idata", "00000.db"), "wb") as handle:
        handle.write(payload)


# --------------------------------------------------------------------------- #
# argument handling
# --------------------------------------------------------------------------- #

def test_default_stage_is_the_cheapest_one():
    # The default must be the floor of the cost curve, not the whole curve: an
    # accidental invocation should cost minutes, not hours.
    assert ghidra_import.resolve_stages(None) == ["import-only"]
    assert ghidra_import.resolve_stages([]) == ["import-only"]


def test_all_expands_to_the_canonical_order():
    assert ghidra_import.resolve_stages(["all"]) == list(ghidra_import.STAGE_ORDER)


def test_stages_are_deduplicated_and_reordered():
    # Cheap before expensive regardless of the order they were asked for: a
    # configuration error should surface on the cheap stage.
    got = ghidra_import.resolve_stages(["default-analysis", "import-only",
                                        "import-only"])
    assert got == ["import-only", "default-analysis"]


def test_comma_separated_stages_are_accepted():
    assert ghidra_import.resolve_stages(["import-only,minimal-analysis"]) == [
        "import-only", "minimal-analysis"]


def test_unknown_stage_is_refused_by_name():
    with pytest.raises(ghidra_import.PrerequisiteError) as caught:
        ghidra_import.resolve_stages(["full-send"])
    assert "full-send" in str(caught.value)
    assert "import-only" in str(caught.value)


def test_every_stage_declares_a_hard_timeout():
    # A stage without a hard timeout can hang forever, and "a truthful partial
    # curve beats a hung run" is the whole timeout policy of this tool.
    for name, spec in ghidra_import.STAGES.items():
        assert spec["hard_timeout"] > 0, name
        if spec["soft_timeout"] is not None:
            # The soft limit must fire first: it stops analysis but SAVES, so the
            # stage still yields a measurable project. If the hard limit fired
            # first there would be nothing to measure.
            assert spec["soft_timeout"] < spec["hard_timeout"], name


def test_no_target_and_no_control_is_a_usage_error(capsys):
    assert ghidra_import.main(["--stage", "import-only"]) == 2
    assert "nothing to measure" in capsys.readouterr().err


def test_unknown_stage_from_the_command_line_exits_two(capsys):
    assert ghidra_import.main(["--stage", "nope", "--target", "x"]) == 2
    assert "nope" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# the command line handed to analyzeHeadless
# --------------------------------------------------------------------------- #

def test_import_only_disables_analysis():
    argv = ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", "import-only")
    assert "-noanalysis" in argv
    assert "-preScript" not in argv
    assert "-analysisTimeoutPerFile" not in argv


def test_minimal_stage_passes_the_prescript_and_its_analyzer_list():
    argv = ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", "minimal-analysis")
    assert "-noanalysis" not in argv
    assert argv[argv.index("-preScript") + 1] == ghidra_import.PRESCRIPT_NAME
    keep = argv[argv.index("-preScript") + 2]
    assert keep.split(";") == list(ghidra_import.MINIMAL_ANALYZERS)
    # The pre-script must be findable: name only on -preScript, directory on
    # -scriptPath, which is what analyzeHeadless documents.
    assert os.path.basename(argv[argv.index("-scriptPath") + 1]) == "ghidra_scripts"


def test_default_stage_passes_no_analyzer_configuration():
    argv = ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", "default-analysis")
    assert "-preScript" not in argv
    assert "-noanalysis" not in argv


def test_soft_timeout_becomes_the_ghidra_analysis_budget():
    argv = ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", "default-analysis",
                                    soft_timeout=90)
    assert argv[argv.index("-analysisTimeoutPerFile") + 1] == "90"


def test_delete_project_is_never_passed():
    # -deleteProject would remove the project after the run, and the project size
    # is half of what T-05 measures. Deletion is this tool's own later step.
    for stage in ghidra_import.STAGE_ORDER:
        argv = ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", stage)
        assert "-deleteProject" not in argv


def test_build_argv_refuses_an_unknown_stage():
    with pytest.raises(ghidra_import.PrerequisiteError):
        ghidra_import.build_argv("AH.bat", "P", "N", "t.exe", "nope")


def test_project_names_are_distinct_per_stage_and_target():
    names = {ghidra_import.project_name_for(stage, role)
             for stage in ghidra_import.STAGE_ORDER
             for role in ("primary", "control")}
    assert len(names) == 2 * len(ghidra_import.STAGE_ORDER)


def test_the_prescript_source_file_exists_and_matches_the_name_passed():
    # A -preScript naming a file that is not there fails four minutes into a
    # 134 MB import, which is an expensive way to find a typo.
    path = os.path.join(ghidra_import.PRESCRIPT_DIR, ghidra_import.PRESCRIPT_NAME)
    assert os.path.isfile(path)
    body = open(path, "r", encoding="utf-8").read()
    stem = os.path.splitext(ghidra_import.PRESCRIPT_NAME)[0]
    # Ghidra requires the public class name to equal the file name.
    assert "public class %s extends GhidraScript" % stem in body


# --------------------------------------------------------------------------- #
# containment: keeping Ghidra's large state off C:
# --------------------------------------------------------------------------- #

def test_all_four_redirecting_properties_are_produced():
    options = ghidra_import.build_vm_options(r"D:\ws")
    joined = " ".join(options)
    for prop in ("application.settingsdir", "application.cachedir",
                 "application.tempdir", "java.io.tmpdir"):
        assert "-D%s=" % prop in joined
    assert len(options) == len(ghidra_import.CONTAINMENT_DIRS)


def test_containment_root_with_a_space_is_refused_with_the_character_named():
    # analyzeHeadless.bat interpolates VM arguments into unquoted cmd.exe
    # variables, so a space would split one property into two arguments and the
    # run would silently use %TEMP% on C: -- exactly the failure the containment
    # exists to prevent, arriving disguised as success.
    with pytest.raises(ghidra_import.PrerequisiteError) as caught:
        ghidra_import.build_vm_options(r"D:\my ws")
    assert "' '" in str(caught.value) or "' '" in repr(caught.value)


@pytest.mark.parametrize("bad", [r"D:\a!b", r"D:\a&b", r"D:\a(b)", r"D:\a%b"])
def test_other_cmd_hostile_characters_are_refused(bad):
    with pytest.raises(ghidra_import.PrerequisiteError):
        ghidra_import.build_vm_options(bad)


def test_environment_pins_the_jdk_ahead_of_path():
    env = ghidra_import.build_environment(
        r"D:\Tools\jdk-21", ["-Dx=1"], maxmem="4G",
        base={"PATH": r"C:\Program Files (x86)\Java8\bin"})
    assert env["JAVA_HOME"] == r"D:\Tools\jdk-21"
    # The bootstrap java that launch.bat uses to run LaunchSupport comes from
    # PATH; on this machine PATH begins with a Java 8 JRE, so the pinned bin must
    # come first, not merely be present.
    assert env["PATH"].startswith(r"D:\Tools\jdk-21\bin" + os.pathsep)
    assert env["GHIDRA_HEADLESS_JAVA_OPTIONS"] == "-Dx=1"
    assert env["GHIDRA_HEADLESS_MAXMEM"] == "4G"


def test_containment_directories_are_created_under_the_given_root(tmp_path):
    created = ghidra_import.ensure_containment(str(tmp_path / "ws"))
    assert set(created) == {key for key, _s, _p in ghidra_import.CONTAINMENT_DIRS}
    for path in created.values():
        assert os.path.isdir(path)


def test_ensure_containment_refuses_a_root_inside_an_installation(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    with pytest.raises(pathguard.OutputPathRefused):
        ghidra_import.ensure_containment(os.path.join(install, "ghidra"),
                                         install_root=install)


# --------------------------------------------------------------------------- #
# the JDK gate
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("banner,major", [
    ('openjdk version "21.0.12.1" 2026-08-18 LTS', 21),
    ('openjdk version "25.0.1" 2025-10-21', 25),
    ('java version "1.8.0_431"', 1),
])
def test_java_major_is_parsed_from_the_banner(banner, major):
    assert ghidra_import.parse_java_major(banner)[0] == major


def test_unparseable_java_banner_yields_no_version():
    assert ghidra_import.parse_java_major("something else entirely") == (None, None)


def test_probe_jdk_refuses_a_home_without_a_java(tmp_path):
    with pytest.raises(ghidra_import.PrerequisiteError) as caught:
        ghidra_import.probe_jdk(str(tmp_path / "not-a-jdk"))
    assert "17.1a" in str(caught.value) or "A-15" in str(caught.value)


def test_required_jdk_major_is_21():
    # plan.md 17.1a / A-15: Ghidra 12.1.3 aborts inside Apache Felix on JDK 25
    # before any user logic runs. A measurement there times a crash.
    assert ghidra_import.REQUIRED_JDK_MAJOR == 21


# --------------------------------------------------------------------------- #
# the guards: writing, importing, deleting
# --------------------------------------------------------------------------- #

def test_import_path_inside_an_installation_is_refused(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    target = os.path.join(install, "MISERY", "Binaries", "Win64",
                          "MISERY-Win64-Shipping.exe")
    with pytest.raises(pathguard.OutputPathRefused) as caught:
        ghidra_import.check_import_path(target, install)
    message = str(caught.value)
    assert "READ-WRITE" in message
    assert "D-01" in message


def test_import_path_inside_an_installation_is_refused_without_being_named(tmp_path):
    # The structural source of protected roots is what makes this work when the
    # invocation names the wrong tree -- the case where a guard keyed only on the
    # argument switches itself off.
    install = make_install_tree(str(tmp_path / "Install"))
    other = make_install_tree(str(tmp_path / "Other"))
    with pytest.raises(pathguard.OutputPathRefused):
        ghidra_import.check_import_path(
            os.path.join(install, "MISERY", "Binaries", "Win64",
                         "MISERY-Win64-Shipping.exe"), other)


def test_import_path_outside_an_installation_is_accepted(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    copy = tmp_path / "ws" / "copy.exe"
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"MZ")
    assert ghidra_import.check_import_path(str(copy), install)


def test_the_real_installation_may_never_be_an_import_path():
    # No argument unlocks the configured root. This asserts the tool's single
    # most important property, and it opens nothing: check_import_path resolves
    # and compares paths.
    real = pathguard.CONFIGURED_INSTALL_ROOTS[0]
    with pytest.raises(pathguard.OutputPathRefused):
        ghidra_import.check_import_path(
            os.path.join(real, "MISERY", "Binaries", "Win64",
                         "MISERY-Win64-Shipping.exe"), None)


@pytest.mark.parametrize("flag", ["--out", "--raw-log-dir", "--evidence-dir"])
def test_output_paths_inside_an_installation_exit_two(tmp_path, capsys, flag):
    install = make_install_tree(str(tmp_path / "Install"))
    bad = os.path.join(install, "pwned.json")
    code = ghidra_import.main([
        "--stage", "import-only", "--target", str(tmp_path / "absent.exe"),
        "--install-dir", install, flag, bad])
    assert code == 2
    assert "D-01" in capsys.readouterr().err
    assert not os.path.exists(bad)


def test_write_text_refuses_a_path_inside_an_installation(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    bad = os.path.join(install, "x.json")
    with pytest.raises(pathguard.OutputPathRefused):
        ghidra_import.write_text("{}", bad, install, "--out")
    assert not os.path.exists(bad)


def test_prepare_copy_refuses_a_destination_inside_an_installation(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    source = tmp_path / "src.exe"
    source.write_bytes(b"MZ")
    with pytest.raises(pathguard.OutputPathRefused):
        ghidra_import.prepare_copy(str(source),
                                   os.path.join(install, "copy.exe"), None,
                                   install_root=install)


def test_prepare_copy_aborts_on_a_digest_mismatch(tmp_path):
    source = tmp_path / "src.exe"
    source.write_bytes(b"MZ payload")
    with pytest.raises(ghidra_import.PrerequisiteError) as caught:
        ghidra_import.prepare_copy(str(source), str(tmp_path / "out" / "c.exe"),
                                   "ff" * 32)
    assert "sha256 mismatch" in str(caught.value)


def test_prepare_copy_records_the_digest_it_verified(tmp_path):
    import hashlib
    source = tmp_path / "src.exe"
    body = b"MZ payload"
    source.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    record = ghidra_import.prepare_copy(str(source),
                                       str(tmp_path / "out" / "c.exe"), digest)
    assert record["sha256"] == digest
    assert record["sha256_matches"] is True
    assert record["bytes"] == len(body)


def test_prepare_copy_rehashes_an_existing_copy(tmp_path):
    # A copy left by an earlier session, on a disk that has been full, is exactly
    # the artifact that must not be trusted on the strength of its filename. The
    # existing file has the right SIZE and the wrong CONTENT.
    import hashlib
    source = tmp_path / "src.exe"
    source.write_bytes(b"AAAA")
    destination = tmp_path / "out" / "c.exe"
    destination.parent.mkdir()
    destination.write_bytes(b"BBBB")
    with pytest.raises(ghidra_import.PrerequisiteError):
        ghidra_import.prepare_copy(str(source), str(destination),
                                   hashlib.sha256(b"AAAA").hexdigest())


def test_delete_project_refuses_paths_inside_an_installation(tmp_path):
    install = make_install_tree(str(tmp_path / "Install"))
    make_project_on_disk(install, "T05-x")
    result = ghidra_import.delete_project(install, "T05-x", install_root=install)
    assert result["removed"] == []
    assert result["errors"]
    assert os.path.exists(os.path.join(install, "T05-x.gpr"))


def test_delete_project_removes_both_halves(tmp_path):
    make_project_on_disk(tmp_path, "T05-x")
    result = ghidra_import.delete_project(str(tmp_path), "T05-x")
    assert len(result["removed"]) == 2
    assert result["errors"] == []
    assert not os.path.exists(os.path.join(str(tmp_path), "T05-x.gpr"))
    assert not os.path.exists(os.path.join(str(tmp_path), "T05-x.rep"))


# --------------------------------------------------------------------------- #
# size measurement
# --------------------------------------------------------------------------- #

def test_project_usage_splits_the_database_from_the_bookkeeping(tmp_path):
    make_project_on_disk(tmp_path, "T05-x", payload=b"y" * 8192)
    usage = ghidra_import.project_usage(str(tmp_path), "T05-x")
    assert usage["gpr"]["bytes"] == 128
    assert usage["rep"]["bytes"] == 8192
    assert usage["bytes"] == 8320
    assert usage["exists"] is True


def test_project_usage_of_an_absent_project_is_zero_not_an_error(tmp_path):
    usage = ghidra_import.project_usage(str(tmp_path), "nothing-here")
    assert usage["bytes"] == 0
    assert usage["exists"] is False


def test_directory_usage_counts_nested_files(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f1").write_bytes(b"x" * 10)
    (tmp_path / "a" / "f2").write_bytes(b"x" * 5)
    usage = ghidra_import.directory_usage(str(tmp_path))
    assert usage["bytes"] == 15
    assert usage["files"] == 2


def test_free_space_sampler_reports_before_min_and_after():
    sampler = ghidra_import.FreeSpaceSampler(volumes=(os.path.abspath(os.sep),),
                                             interval=0.01).start()
    report = sampler.stop()
    volume = os.path.abspath(os.sep)
    assert report[volume]["samples"] >= 2
    for key in ("free_before_bytes", "free_min_bytes", "free_after_bytes",
                "consumed_peak_bytes"):
        assert key in report[volume]


# --------------------------------------------------------------------------- #
# parsing what Ghidra says about itself
# --------------------------------------------------------------------------- #

def test_parser_reads_the_analyzer_table_and_the_total():
    parsed = ghidra_import.parse_ghidra_report(CANNED_DEFAULT_LOG)
    assert parsed["total_time_seconds"] == 7
    assert parsed["analyzer_count"] == 3
    assert parsed["analyzer_seconds"]["Decompiler Parameter ID"] == 3.029
    assert parsed["analysis_succeeded_line"] is True
    assert parsed["import_succeeded_line"] is True
    assert parsed["warn_lines"] == 1
    assert parsed["error_lines"] == 0


def test_parser_reads_the_prescript_result():
    parsed = ghidra_import.parse_ghidra_report(CANNED_MINIMAL_LOG)
    assert parsed["prescript_enabled_analyzers"] == ["ASCII Strings", "Reference"]
    assert parsed["prescript_enabled_count"] == 2


def test_absent_timing_table_is_reported_as_none_not_zero():
    # Ghidra prints the table only when analysis took at least a second. A None
    # means "Ghidra reported no table", which for a fast stage is the truth; a 0
    # would assert that analysis took no time, which is a different claim.
    parsed = ghidra_import.parse_ghidra_report(CANNED_MINIMAL_LOG)
    assert parsed["total_time_seconds"] is None
    assert parsed["analyzer_count"] == 0


def test_parser_survives_empty_output():
    parsed = ghidra_import.parse_ghidra_report("")
    assert parsed["total_time_seconds"] is None
    assert parsed["report_lines"] == []


# --------------------------------------------------------------------------- #
# outcome classification -- a timeout is a result
# --------------------------------------------------------------------------- #

def test_outcome_completed():
    parsed = ghidra_import.parse_ghidra_report(CANNED_DEFAULT_LOG)
    result = {"timed_out": False, "exit_code": 0}
    assert ghidra_import.classify_outcome(result, {"exists": True}, 3600,
                                          parsed) == "completed"


def test_outcome_hard_timeout_is_named_as_a_kill():
    parsed = ghidra_import.parse_ghidra_report("")
    result = {"timed_out": True, "exit_code": 1}
    assert ghidra_import.classify_outcome(result, {"exists": True}, 3600,
                                          parsed) == "hard-timeout-process-killed"


def test_outcome_soft_timeout_is_distinguished_from_a_kill():
    # Ghidra's own budget expired: analysis stopped, the program was SAVED, and
    # the project size is real. That is a usable data point; a killed process is
    # not, and the report must not spell them the same way.
    parsed = ghidra_import.parse_ghidra_report(
        CANNED_DEFAULT_LOG.replace("Total Time   7 secs", "Total Time   600 secs"))
    result = {"timed_out": False, "exit_code": 0}
    assert ghidra_import.classify_outcome(result, {"exists": True}, 600,
                                          parsed) == "soft-timeout-analysis-aborted"


def test_outcome_nonzero_exit():
    parsed = ghidra_import.parse_ghidra_report("")
    result = {"timed_out": False, "exit_code": 3}
    assert ghidra_import.classify_outcome(result, {"exists": True}, None,
                                          parsed) == "nonzero-exit"


def test_outcome_notices_a_missing_project():
    parsed = ghidra_import.parse_ghidra_report(CANNED_DEFAULT_LOG)
    result = {"timed_out": False, "exit_code": 0}
    assert ghidra_import.classify_outcome(
        result, {"exists": False}, None, parsed) == "completed-no-project-on-disk"


# --------------------------------------------------------------------------- #
# the report shape, built through run_stage with an injected runner
# --------------------------------------------------------------------------- #

@pytest.fixture()
def staged(tmp_path):
    """One completed stage record, produced without Ghidra existing."""
    target = make_target(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    make_project_on_disk(projects,
                         ghidra_import.project_name_for("default-analysis",
                                                        "primary"))
    seen: list = []
    record = ghidra_import.run_stage(
        "default-analysis", target,
        launcher="AH.bat", project_root=str(projects),
        env={"PATH": "x"}, vm_options=["-Dx=1"],
        raw_log_dir=str(tmp_path / "raw"),
        evidence_dir=str(tmp_path / "evidence"),
        redactor=FakeRedactor(), keep_project=True,
        runner=make_runner(CANNED_DEFAULT_LOG, seen=seen))
    return record, seen, tmp_path


def test_stage_record_carries_every_number_t05_asks_for(staged):
    record, _seen, _tmp = staged
    # These four are exactly what the task says to record after each stage.
    assert record["wall_clock_seconds"] == 12.5
    assert record["project"]["bytes"] == 128 + 4096
    assert record["exit_code"] == 0
    for volume in ghidra_import.WATCHED_VOLUMES:
        if volume in record["disk"]:
            assert "free_min_bytes" in record["disk"][volume]


def test_stage_record_states_its_configuration_not_just_its_result(staged):
    record, _seen, _tmp = staged
    # A measurement whose configuration is not recorded alongside it cannot be
    # reused or re-run, which is the whole point of writing it down.
    assert record["argv"][0] == "AH.bat"
    assert record["vm_options"] == ["-Dx=1"]
    assert record["soft_analysis_timeout_seconds"] == \
        ghidra_import.STAGES["default-analysis"]["soft_timeout"]
    assert record["hard_process_timeout_seconds"] == \
        ghidra_import.STAGES["default-analysis"]["hard_timeout"]
    assert record["target_sha256"] == "0" * 64
    assert record["outcome"] == "completed"


def test_stage_record_normalises_cost_against_target_size(staged):
    record, _seen, _tmp = staged
    # The curve RISK-13 asks about is cost per unit of input, so the ratios are
    # recorded rather than left to whoever reads the report to divide.
    assert record["seconds_per_megabyte"] == pytest.approx(
        12.5 / (134658048 / (1 << 20)), rel=1e-5)
    # Six SIGNIFICANT figures, not six decimal places. These ratios span orders
    # of magnitude, and decimal rounding turned this one into 0.0 -- a wrong
    # number wearing the clothes of a rounded one. The regression is kept.
    assert record["project_bytes_per_target_byte"] == pytest.approx(
        4224 / 134658048, rel=1e-5)


@pytest.mark.parametrize("value,expected", [
    (0.0973369226, 0.0973369),
    (3.136834420769266e-05, 3.13683e-05),
    (31.4159265, 31.4159),
    (0.0, 0.0),
])
def test_significant_keeps_small_ratios_from_collapsing(value, expected):
    assert ghidra_import.significant(value) == pytest.approx(expected, rel=1e-9)


def test_the_hard_timeout_reaches_the_runner(staged):
    _record, seen, _tmp = staged
    assert seen[0]["timeout"] == \
        ghidra_import.STAGES["default-analysis"]["hard_timeout"]


def test_raw_log_is_written_outside_the_evidence_directory(staged):
    record, _seen, tmp_path = staged
    raw = record["log"]["raw_path"]
    assert os.path.isfile(raw)
    assert "raw" in os.path.basename(os.path.dirname(raw))
    assert record["log"]["raw_bytes"] == len(CANNED_DEFAULT_LOG.encode("utf-8"))
    assert len(record["log"]["raw_sha256"]) == 64


def test_redacted_log_is_written_when_redaction_is_clean(staged):
    record, _seen, _tmp = staged
    assert record["log"]["redaction_residual_profile_paths"] == 0
    assert os.path.isfile(record["log"]["redacted_path"])


def test_a_surviving_profile_path_blocks_the_committed_log(tmp_path):
    # C-13: the repository is public. A partially redacted log is a violation,
    # not a warning, so the file must simply not appear -- while the raw capture,
    # which lives outside git, still does, so nothing is lost locally.
    target = make_target(tmp_path)
    leaky = CANNED_DEFAULT_LOG + "INFO  wrote C:\\Users\\somebody\\thing.log\n"
    record = ghidra_import.run_stage(
        "import-only", target, launcher="AH.bat",
        project_root=str(tmp_path / "projects"), env={}, vm_options=[],
        raw_log_dir=str(tmp_path / "raw"),
        evidence_dir=str(tmp_path / "evidence"),
        redactor=FakeRedactor(actually_redact=False),
        runner=make_runner(leaky))
    assert record["log"]["redaction_residual_profile_paths"] == 1
    assert record["log"]["redacted_path"] is None
    assert "C-13" in record["log"]["redacted_note"]
    assert os.path.isfile(record["log"]["raw_path"])
    assert not os.path.isdir(str(tmp_path / "evidence"))


def test_the_real_redactor_removes_a_profile_path():
    # The fake redactor above proves the wiring; this proves the wiring is
    # connected to something that works. Loaded by path from T-02 rather than
    # copied, so there is one set of redaction rules in the repository.
    redactor = ghidra_import.load_redactor()
    text = "INFO  log at %s\\ghidra\\application.log" % os.environ.get(
        "APPDATA", "C:\\Users\\nobody\\AppData\\Roaming")
    redacted, residual = ghidra_import.redact_log(text, redactor)
    assert residual == 0
    if os.environ.get("APPDATA"):
        assert "%APPDATA%" in redacted


def test_project_is_deleted_after_measurement_by_default(tmp_path):
    target = make_target(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    name = ghidra_import.project_name_for("import-only", "primary")
    make_project_on_disk(projects, name)
    record = ghidra_import.run_stage(
        "import-only", target, launcher="AH.bat", project_root=str(projects),
        env={}, vm_options=[], raw_log_dir=str(tmp_path / "raw"),
        evidence_dir=None, redactor=FakeRedactor(),
        runner=make_runner(CANNED_DEFAULT_LOG))
    # The size was read BEFORE the deletion; that ordering is the whole reason
    # deleting by default is safe.
    assert record["project"]["bytes"] > 0
    assert record["project_kept"] is False
    assert not os.path.exists(os.path.join(str(projects), name + ".gpr"))


def test_containment_directories_are_measured_when_a_root_is_given(tmp_path):
    # The project directory is NOT where the bytes are while the work happens:
    # the first real 134 MB run had 753 MiB in the redirected temp directory
    # while the .rep was still 4 KiB, because Ghidra writes the database at save
    # time. A report carrying only the final project size understates the
    # transient footprint, and the transient footprint is what RISK-13 is about.
    root = tmp_path / "ws"
    created = ghidra_import.ensure_containment(str(root))
    with open(os.path.join(created["ghidra_temp_dir"], "scratch"), "wb") as handle:
        handle.write(b"z" * 2048)
    record = ghidra_import.run_stage(
        "import-only", make_target(tmp_path), launcher="AH.bat",
        project_root=str(tmp_path / "projects"), env={}, vm_options=[],
        raw_log_dir=str(tmp_path / "raw"), evidence_dir=None,
        redactor=FakeRedactor(), containment_root=str(root),
        runner=make_runner(CANNED_DEFAULT_LOG))
    usage = record["containment_usage_after"]
    assert usage["ghidra_temp_dir"]["bytes"] == 2048
    assert set(usage) == {key for key, _s, _p in ghidra_import.CONTAINMENT_DIRS}


def test_containment_measurement_is_omitted_when_no_root_is_given(tmp_path):
    record = ghidra_import.run_stage(
        "import-only", make_target(tmp_path), launcher="AH.bat",
        project_root=str(tmp_path / "projects"), env={}, vm_options=[],
        raw_log_dir=str(tmp_path / "raw"), evidence_dir=None,
        redactor=FakeRedactor(), runner=make_runner(""))
    assert "containment_usage_after" not in record


def test_document_shape_is_json_serialisable_and_complete(staged):
    record, _seen, _tmp = staged
    document = ghidra_import.build_document(
        targets=[{"role": "primary", "copy": "c.exe", "bytes": 1,
                  "sha256": "0" * 64, "sha256_matches": True}],
        stages=[record], jdk={"version": "21.0.12.1", "major": 21},
        ghidra={"application_name": "Ghidra", "application_version": "12.1.3"},
        containment={"settings_dir": "D:\\x"}, vm_options=["-Dx=1"],
        maxmem="4G", notes=["a note"])
    for key in ("generator", "generator_version", "generated_at", "question",
                "task", "environment", "containment", "targets", "stages",
                "notes"):
        assert key in document
    text = ghidra_import.dump_json(document)
    assert json.loads(text)["stages"][0]["stage"] == "default-analysis"
    assert text.endswith("\n")


def test_summary_renders_without_a_traceback(staged):
    record, _seen, _tmp = staged
    document = ghidra_import.build_document(
        targets=[{"role": "primary", "copy": "c.exe", "bytes": 134658048,
                  "sha256": "0" * 64, "sha256_matches": True}],
        stages=[record], jdk={"version": "21.0.12.1", "major": 21},
        ghidra={"application_name": "Ghidra", "application_version": "12.1.3"},
        containment={}, vm_options=[], maxmem="4G")
    text = ghidra_import.format_summary(document)
    assert "default-analysis" in text
    assert "completed" in text


def test_digest_mismatch_is_shouted_in_the_summary():
    document = ghidra_import.build_document(
        targets=[{"role": "primary", "copy": "c.exe", "bytes": 1,
                  "sha256": "0" * 64, "sha256_matches": False}],
        stages=[], jdk={}, ghidra={}, containment={}, vm_options=[], maxmem="2G")
    assert "DIGEST MISMATCH" in ghidra_import.format_summary(document)


# --------------------------------------------------------------------------- #
# --plan runs nothing
# --------------------------------------------------------------------------- #

def test_plan_prints_the_commands_and_starts_no_process(tmp_path, capsys,
                                                        monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("--plan started a process")

    monkeypatch.setattr(ghidra_import, "run_process", explode)
    monkeypatch.setattr(ghidra_import.subprocess, "Popen", explode)
    monkeypatch.setattr(ghidra_import.subprocess, "run", explode)

    source = tmp_path / "src.exe"
    source.write_bytes(b"MZ" + b"\0" * 30)
    code = ghidra_import.main([
        "--plan", "--stage", "all", "--target", str(source),
        "--copy-dir", str(tmp_path / "bin"),
        "--containment-root", str(tmp_path / "ws"),
        "--project-root", str(tmp_path / "projects")])
    assert code == 0
    out = capsys.readouterr().out
    assert "-noanalysis" in out
    assert ghidra_import.PRESCRIPT_NAME in out
    for stage in ghidra_import.STAGE_ORDER:
        assert stage in out


def test_generator_identity_is_recorded():
    assert ghidra_import.GENERATOR_NAME == "tools/static/ghidra_import.py"
    assert ghidra_import.GENERATOR_VERSION.count(".") == 2
