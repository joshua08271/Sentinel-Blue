"""Read-only PowerShell 5.1 contract checks, run after the setup timer stops."""
import time


def verify():
    from sentinel_blue.windows_queries import WINDOWS_QUERIES
    from sentinel_blue.windows_query_batch import read_query_batch
    queries = {
        'FIRST': "$sbOnlyFirst='fixture'; [PSCustomObject]@{PID=$PID;Name='蓝 Ω'} | ConvertTo-Json -Compress",
        'EMPTY_EVENTS': "function Get-WinEvent { [CmdletBinding()] param($FilterHashtable,$MaxEvents) }\n"
                        + WINDOWS_QUERIES['SECURITY_EVENTS'],
        'NONTERMINATING': "$ErrorActionPreference='Continue'; Write-Error 'owned query error fixture'; "
                          "[PSCustomObject]@{Name='partial'} | ConvertTo-Json -Compress",
        'TERMINATING': "throw 'owned query exception fixture'",
        'LAST': "[PSCustomObject]@{PID=$PID;ScopeClean=($null -eq (Get-Variable sbOnlyFirst -ErrorAction SilentlyContinue));"
                "PreferenceClean=($ErrorActionPreference -eq 'Stop')} | ConvertTo-Json -Compress",
    }
    rows = read_query_batch(time.monotonic()+30, queries)
    first, last = rows['FIRST'], rows['LAST']
    checks = {
        'unicode_preserved': not first.error and first.rows[0].get('Name') == '蓝 Ω',
        'empty_event_query_continues': not rows['EMPTY_EVENTS'].error and rows['EMPTY_EVENTS'].rows == [] and not last.error,
        'nonterminating_error_rejected': bool(rows['NONTERMINATING'].error),
        'terminating_error_rejected': bool(rows['TERMINATING'].error),
        'later_section_survives_failure': not last.error and bool(last.rows),
        'one_native_process': not first.error and not last.error and first.rows[0].get('PID') == last.rows[0].get('PID'),
        'section_variables_isolated': not last.error and last.rows[0].get('ScopeClean') is True,
        'error_preference_isolated': not last.error and last.rows[0].get('PreferenceClean') is True,
    }
    return {'passed': all(checks.values()), 'checks': checks}
