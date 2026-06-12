"""claudeagent: a lean, model-driven harness for binary patch-presence testing.

Given one project, one CVE, and one target binary, a DeepSeek model uses bounded
binutils observations to decide a verdict (present / absent / not_affected /
inconclusive). The verdict is produced by the model calling a finalization tool
after a controlled tool loop, never by a CVE-specific pattern matcher.
"""
