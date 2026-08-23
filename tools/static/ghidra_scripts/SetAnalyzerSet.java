/* Restrict Ghidra auto-analysis to a named list of analyzers (plan.md T-05).
 *
 * WHY THIS SCRIPT EXISTS
 * ----------------------
 * analyzeHeadless has exactly one command-line lever over the analyzer set:
 * -noanalysis, which turns all of it off. There is no flag that says "run these
 * four analyzers and no others", and T-05 needs precisely that: a middle point
 * on the cost curve between "import only" and "the default set", so that the
 * measured numbers describe a curve rather than two endpoints.
 *
 * The supported way to reach that middle point is a pre-script: -preScript runs
 * before auto-analysis, the analyzer enablement flags live in the program's own
 * analysis options, and AutoAnalysisManager reads those options when it starts.
 * So this script edits the options and then gets out of the way. It performs no
 * analysis of its own -- tools/static/ghidra_import.py must not reimplement
 * analysis, and neither must its pre-script.
 *
 * WHAT IT DOES, EXACTLY
 * ---------------------
 * Argument 0 is a semicolon-separated list of analyzer names to KEEP enabled.
 * Every analysis option whose name contains no '.' is an analyzer enablement
 * toggle (the dotted names are that analyzer's own settings); every such toggle
 * whose current value is the string "true" or "false" is set to "true" if it is
 * named in the keep list and to "false" otherwise. A toggle whose value is not
 * boolean is left alone and reported, because guessing at it would silently
 * change something this script does not understand.
 *
 * With no argument, or an empty argument, every analyzer is disabled. That is a
 * legitimate configuration (it is a slower spelling of -noanalysis) and is not
 * treated as an error.
 *
 * WHY IT PRINTS SO MUCH
 * ---------------------
 * Every line it prints is prefixed SETANALYZERSET: and goes into the captured
 * analyzeHeadless log, which is the evidence artifact. The full option
 * inventory is printed BEFORE the change and the resulting enabled set AFTER
 * it, so the log answers "which analyzers did this measurement actually run?"
 * from its own contents. A measurement whose configuration is only known from
 * the invoking script's intent is not a measurement of anything checkable.
 *
 * A name in the keep list that matches no toggle is printed as a WARNING and
 * does not stop the run: the caller's spelling of an analyzer name is a guess
 * about a third-party tool, and the honest outcome is a recorded discrepancy,
 * not a crash that loses the timing.
 *
 * @category MISERY
 */

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;

public class SetAnalyzerSet extends GhidraScript {

	/** Prefix on every line this script emits, so the log can be grepped. */
	private static final String TAG = "SETANALYZERSET: ";

	@Override
	protected void run() throws Exception {

		Set<String> keep = parseKeepList(getScriptArgs());
		println(TAG + "keep_requested=" + keep.size());
		for (String name : keep) {
			println(TAG + "keep_requested_name=" + name);
		}

		if (currentProgram == null) {
			// A pre-script in -import mode always has a program; saying so
			// explicitly is cheaper than debugging a NullPointerException in a
			// log that is supposed to be evidence.
			println(TAG + "ERROR no current program, analysis options unchanged");
			return;
		}

		Map<String, String> before = getCurrentAnalysisOptionsAndValues(currentProgram);
		List<String> names = new ArrayList<>(before.keySet());
		Collections.sort(names);

		println(TAG + "option_inventory_size=" + names.size());
		List<String> toggles = new ArrayList<>();
		for (String name : names) {
			String value = before.get(name);
			println(TAG + "option=" + name + " value=" + value);
			if (name.indexOf('.') < 0 && isBooleanText(value)) {
				toggles.add(name);
			}
			else if (name.indexOf('.') < 0) {
				// Dot-free but not boolean: not an enablement toggle as this
				// script understands the word. Reported, never written to.
				println(TAG + "skipped_non_boolean_toggle=" + name + " value=" + value);
			}
		}
		println(TAG + "toggle_count=" + toggles.size());

		Map<String, String> wanted = new LinkedHashMap<>();
		for (String toggle : toggles) {
			wanted.put(toggle, keep.contains(toggle) ? "true" : "false");
		}
		setAnalysisOptions(currentProgram, wanted);

		for (String name : keep) {
			if (!toggles.contains(name)) {
				println(TAG + "WARNING keep name is not an analyzer toggle: " + name);
			}
		}

		// Read the options back rather than trusting the write. The enabled set
		// reported here is the one the analyzer will see, not the one we asked
		// for, and those are different claims.
		Map<String, String> after = getCurrentAnalysisOptionsAndValues(currentProgram);
		int enabled = 0;
		for (String toggle : toggles) {
			if ("true".equalsIgnoreCase(after.get(toggle))) {
				enabled++;
				println(TAG + "enabled=" + toggle);
			}
		}
		println(TAG + "enabled_count=" + enabled +
			" disabled_count=" + (toggles.size() - enabled));
		println(TAG + "done");
	}

	/** Split argument 0 on ';', trimming and dropping empties. */
	private Set<String> parseKeepList(String[] args) {
		Set<String> keep = new LinkedHashSet<>();
		if (args == null || args.length == 0 || args[0] == null) {
			return keep;
		}
		for (String part : args[0].split(";")) {
			String trimmed = part.trim();
			if (!trimmed.isEmpty()) {
				keep.add(trimmed);
			}
		}
		return keep;
	}

	private boolean isBooleanText(String value) {
		return "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
	}
}
