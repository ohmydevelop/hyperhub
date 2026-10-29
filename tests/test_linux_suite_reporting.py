"""Deterministic report/capability contracts; no CLI, Cargo, VM or sysctl writes."""
import csv
import json
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'scripts/lib/linux-suite.sh'
REPORT = ROOT / 'tests/benchmarks/linux-static/suite_report.py'


class ReportingTests(unittest.TestCase):
    def report(self, rows):
        with tempfile.TemporaryDirectory(prefix='hh-suite-report-') as name:
            directory = Path(name)
            with (directory/'checks.tsv').open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=['check','status','details'], delimiter='\t')
                writer.writeheader()
                for check,status in rows:
                    writer.writerow({'check':check,'status':status,'details':'unit-test input'})
            (directory/'summary.csv').write_text('workload,kind,binary_bytes,native_median_ms,hyperhub_median_ms,overhead_ms,overhead_ratio\n')
            (directory/'fixtures.json').write_text(json.dumps({'architecture':'unit-test','probe_fingerprint':'0'*64,'fixtures':[]}))
            result = subprocess.run(['python3',str(REPORT),*[str(directory/file) for file in ['checks.tsv','summary.csv','fixtures.json','suite.json','report.md']]],capture_output=True,text=True)
            return result.returncode,json.loads((directory/'suite.json').read_text()),(directory/'report.md').read_text()

    def test_complete_execution_reports_pass(self):
        code,result,text = self.report([('ptrace','pass'),('gum','pass')])
        self.assertEqual(code,0)
        self.assertEqual(result['status'],'pass')
        self.assertTrue(result['coverage_complete'])
        self.assertEqual(result['executed_checks'],2)
        self.assertIn('**Result: PASS**',text)

    def test_restricted_environment_is_partial_not_full_green(self):
        code,result,text = self.report([('ptrace','pass'),('gum.positive','skip'),('gum.refusal','pass')])
        self.assertEqual(code,0)
        self.assertEqual(result['status'],'partial')
        self.assertFalse(result['coverage_complete'])
        self.assertEqual((result['executed_checks'],result['skipped_checks']),(2,1))
        self.assertIn('**Result: PARTIAL**',text)
        self.assertNotIn('**Result: PASS**',text)

    def test_rejection_only_mode_never_claims_complete_suite(self):
        code,result,_ = self.report([('attach-tree','pass'),('attach-process','pass'),('run-tree','pass'),('coverage.full_linux_suite','skip')])
        self.assertEqual(code,0)
        self.assertEqual(result['status'],'partial')
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['executed_checks'],3)

    def test_failure_wins_over_skipped_checks(self):
        code,result,_ = self.report([('ptrace','fail'),('gum','skip')])
        self.assertNotEqual(code,0)
        self.assertEqual(result['status'],'fail')
        self.assertFalse(result['coverage_complete'])

    def test_empty_unknown_and_duplicate_checks_do_not_pass(self):
        for rows in [[],[('unknown','unexpected')],[('duplicate','pass'),('duplicate','pass')]]:
            with self.subTest(rows=rows):
                code,result,text = self.report(rows)
                self.assertNotEqual(code,0)
                self.assertEqual(result['status'],'fail')
                self.assertFalse(result['coverage_complete'])
                self.assertNotIn('**Result: PASS**',text)


class CapabilityTests(unittest.TestCase):
    def classify(self, value=None, *, missing=False, directory=False):
        with tempfile.TemporaryDirectory(prefix='hh-suite-capability-') as name:
            path = Path(name)/'mock-yama'
            if directory:path.mkdir()
            elif not missing:path.write_text(value)
            command = 'source "$1"; linux_suite_classify_yama "$2"; printf "%s\\t%s\\t%s\\n" "$linux_gum_available" "$linux_gum_negative" "$linux_yama_scope"'
            result = subprocess.run(['bash','-eu','-c',command,'test',str(HELPER),str(path)],capture_output=True,text=True,check=True,cwd=path.parent)
            self.assertFalse((path.parent/'sentinel').exists())
            return result.stdout.strip().split('\t')

    def test_unrestricted_and_absent_yama_match_cli_support(self):
        self.assertEqual(self.classify(' 0\n'),['1','0','0'])
        self.assertEqual(self.classify(missing=True),['1','0','absent'])

    def test_restricted_modes_schedule_rejection_cases(self):
        for mode in ['1','2','3']:
            self.assertEqual(self.classify(mode+'\n'),['0','1',mode])

    def test_unknown_or_unreadable_never_allows_gum_positive(self):
        for value in ['', '99', '0\n1', 'invalid', '$(touch sentinel)']:
            self.assertEqual(self.classify(value),['0','0','unknown'])
        self.assertEqual(self.classify(directory=True),['0','0','unknown'])

    def test_dispatcher_skips_gum_but_really_executes_ptrace(self):
        with tempfile.TemporaryDirectory(prefix='hh-suite-dispatch-') as name:
            path = Path(name)
            (path/'scope').write_text('1\n')
            script = '''source "$1"
linux_suite_classify_yama "$2/scope"
checks_file="$2/checks.tsv"
probe() { printf '%s\n' "$1" >> "$2/executed"; }
linux_suite_run_backend gum gum.positive unused probe gum "$2"
linux_suite_run_backend ptrace ptrace.positive executed probe ptrace "$2"
'''
            subprocess.run(['bash','-eu','-c',script,'test',str(HELPER),str(path)],check=True)
            self.assertEqual((path/'executed').read_text().splitlines(),['ptrace'])
            rows = list(csv.reader((path/'checks.tsv').read_text().splitlines(),delimiter='\t'))
            self.assertEqual([(row[0],row[1]) for row in rows],[('gum.positive','skip'),('ptrace.positive','pass')])
            self.assertIn('scope 1',rows[0][2])

    def test_nested_hook_plan_preserves_ptrace_and_reports_every_gum_group(self):
        path=ROOT/'tests/benchmarks/linux-static/hook_regressions.py'
        spec=importlib.util.spec_from_file_location('hook_capability_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        backends,skips=module.backend_plan(False,'test restricted Yama')
        self.assertEqual(backends,('ptrace',))
        self.assertEqual({row['check'] for row in skips},
                         {'gum.loader_exit','gum.fast_open','gum.exit_variants',
                          'gum.mapping_permissions','gum.execve_errors'})
        self.assertTrue(all(row['status']=='skip' and row['details']=='test restricted Yama' for row in skips))
        self.assertEqual(module.backend_plan(True,'unrestricted'),(('ptrace','gum'),[]))

    def test_legal_gum_failure_is_not_converted_to_skip(self):
        with tempfile.TemporaryDirectory(prefix='hh-suite-dispatch-') as name:
            path = Path(name)
            (path/'scope').write_text('0\n')
            script = '''source "$1"
linux_suite_classify_yama "$2/scope"
checks_file="$2/checks.tsv"
probe() { return 7; }
linux_suite_run_backend gum gum.positive expected-failure probe
'''
            result = subprocess.run(['bash','-eu','-c',script,'test',str(HELPER),str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,7)
            rows = list(csv.reader((path/'checks.tsv').read_text().splitlines(),delimiter='\t'))
            self.assertEqual(rows[0][1],'fail')


if __name__ == '__main__':
    unittest.main()
