#!/usr/bin/env python3
"""Run isolated wrong-byte and known 3ms-origin-cost benchmark mutations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import stat
import subprocess
import sys

REPO=Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--build-dir",type=Path,help="Optional reusable build directory private to isolated sensitivity packages")
    parser.add_argument("--profile",choices=["dev","release"],default="release")
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    expected=digest(args.worker.resolve())
    worker=output/("candidate-worker"+(".exe" if os.name=="nt" else ""))
    shutil.copyfile(args.worker.resolve(),worker)
    if digest(worker)!=expected or digest(args.worker.resolve())!=expected:
        raise RuntimeError("candidate executable changed while making its sensitivity snapshot")
    worker.chmod(stat.S_IRUSR|stat.S_IXUSR)
    temporary=output/"tmp";temporary.mkdir(mode=0o700)
    build=args.build_dir.resolve() if args.build_dir else output/"build"
    if build==REPO/"target":
        parser.error("sensitivity builds must not share the root workspace target directory")
    source=REPO/"crates/hyperhub-core/tests/forward_worker_benchmark.rs"
    support=REPO/"crates/hyperhub-core/tests/forward_workers/support.rs"
    resources=REPO/"crates/hyperhub-core/tests/forward_worker_benchmark/resources.rs"
    bound = [source,support,resources]
    bound.extend(REPO / item["path"] for item in json.loads((REPO/"benchmarks/forward-workers/model.json").read_text())["sources"])
    original={str(path):digest(path) for path in bound}
    summary={"scope":"Independent payload oracle and fixed-supply echo measurement only; other critical flow obligations are not mutation-covered.",
             "criterion":"Each of three cost-mutated trial medians must exceed the maximum of three normal trial medians by at least 2500 us. Wrong-byte mutation must fail the independent byte oracle before formal samples.",
             "source_fingerprints":original,"worker_sha256":digest(worker),"results":{}}
    for mode in ["normal","wrong-byte","cost-3ms"]:
        root=output/mode;(root/"tests").mkdir(parents=True)
        (root/"Cargo.toml").write_text(f'''[package]\nname="hh-forward-sensitivity-{mode}"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[dependencies]\nhyperhub-core={{path={json.dumps(str(REPO/'crates/hyperhub-core'))}}}\nserde_json="1"\ntokio={{version="1",features=["full"]}}\nsha2="0.10"\nrand="0.10"\nrustls={{version="0.23",default-features=false,features=["ring","std","tls12"]}}\n''',encoding="utf-8")
        shutil.copy(REPO/"Cargo.lock",root/"Cargo.lock")
        code=source.read_text().replace("forward_worker_benchmark/resources.rs","resources.rs").replace("forward_workers/support.rs","support.rs")
        code=code[:code.index("    for trial in 0..5 {")]+'''    for trial in 0..3 {
        results.push(scenario("baseline",trial).await);
        std::fs::write(&output,serde_json::to_vec_pretty(&json!({"schema":1,"trials":results})).unwrap()).unwrap();
    }
}
'''
        (root/"tests/benchmark.rs").write_text(code,encoding="utf-8")
        code=support.read_text().replace('assert_eq!(result, value);','assert_eq!(result, value, "independent payload oracle");')
        needle='stream.write_all(&bytes[..count]).await.unwrap();'
        if mode=="wrong-byte":
            assert code.count(needle)==1
            code=code.replace(needle,'bytes[0] ^= 1;\n                    '+needle)
        if mode=="cost-3ms":
            assert code.count(needle)==1
            code=code.replace(needle,'tokio::time::sleep(Duration::from_millis(3)).await;\n                    '+needle)
        (root/"tests/support.rs").write_text(code,encoding="utf-8")
        shutil.copy(resources,root/"tests/resources.rs")
        env=os.environ.copy();env["CARGO_INCREMENTAL"]="0";env["CARGO_TARGET_DIR"]=str(build)
        for name in ("TMPDIR","TMP","TEMP"):env[name]=str(temporary)
        env["HH_FORWARD_WORKER_FIXTURE"]=str(worker)
        env["HH_FORWARD_BENCHMARK_OUTPUT"]=str(root/"raw.json")
        command=["cargo","test","--manifest-path",str(root/"Cargo.toml"),"--test","benchmark","--offline"]
        if args.profile=="release":command.append("--release")
        command.extend(["--","--ignored","--nocapture"])
        with (root/"run.log").open("wb") as log:
            log.write((json.dumps(command)+"\n").encode());log.flush()
            process=subprocess.Popen(command,cwd=REPO,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            assert process.stdout is not None
            with process.stdout:
                while chunk:=process.stdout.read1(65536):
                    log.write(chunk);log.flush()
            status=process.wait()
        result={"exit_code":status,"log_sha256":digest(root/"run.log"),"mutation_sha256":digest(root/"tests/support.rs")}
        if mode=="wrong-byte":
            result["detected"]=status!=0 and "independent payload oracle" in (root/"run.log").read_text() and not (root/"raw.json").exists()
        elif status==0:
            rows=json.loads((root/"raw.json").read_text())["trials"]
            assert len(rows)==3 and all(len(row["echo_us"])==1024 for row in rows)
            result["median_echo_us"]=[statistics.median(row["echo_us"]) for row in rows]
            result["raw_sha256"]=digest(root/"raw.json")
        summary["results"][mode]=result
        (output/"summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    normal=summary["results"]["normal"].get("median_echo_us",[])
    cost=summary["results"]["cost-3ms"].get("median_echo_us",[])
    summary["cost_detected"]=len(normal)==3 and len(cost)==3 and min(cost)>max(normal)+2500
    summary["sources_unchanged"]=all(digest(Path(path))==value for path,value in original.items())
    passed=summary["sources_unchanged"] and summary["cost_detected"] and summary["results"]["wrong-byte"].get("detected",False)
    summary["passed"]=passed
    (output/"summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))
    return 0 if passed else 1

if __name__=="__main__":
    sys.exit(main())
