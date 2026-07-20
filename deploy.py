import subprocess
import os
import sys
import glob

NAMESPACE = os.getenv("KUBE_NAMESPACE")
REGISTRY = os.getenv("REGISTRY_IMAGE")
TAG = os.getenv("CI_COMMIT_SHORT_SHA")
COMPONENT = sys.argv[1]
PREFIX = os.getenv("PREFIX", "")

if not TAG:
    try:
        result = subprocess.run(
                ["git", "rev-parse", "--short=8", "HEAD"],
                capture_output=True, text=True, check=True
        )
        TAG = result.stdout.strip()
        print(f"Commit SHA not set", flush=True)
    except subprocess.CalledProcessError:
        print(f"Error: Commit SHA not set and rev-parse failed", file=sys.stderr)
        sys.exit(1)

if len(TAG) != 8:
    print(
        f"Error: SHA length - {len(TAG)} characters ('{TAG}') - Expected 8\n",
        file=sys.stderr
    )
    sys.exit(1)

# Expose the resolved tag to envsubst so manifests can pin `image: .../{comp}:${IMAGE_TAG}`
# at render time. This replaces the old post-apply `kubectl set image` override, so the
# manifest that gets applied is the one that actually runs (and that policy checks can see).
os.environ["IMAGE_TAG"] = TAG

def run_script(cmd, check=True):
    print(f"$ {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, text=True)
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result

def render_manifest(path): # Reads manifest files
    with open(path) as f:
        rendered = subprocess.run(
                ["envsubst"],
                input=f.read(),
                text=True,
                capture_output=True,
                check=True
        ).stdout
    return rendered 

def apply_manifest(path): # Renders a manifest by using envsubst 
    rendered = render_manifest(path)
    subprocess.run(
            ["kubectl", "apply", "-f", "-", "-n", NAMESPACE],
            input=rendered,
            text=True,
            check=True
        )

def apply_manifests(component): # Applies all manifests
    for directory in ["K3s/base", "K3s/database", "K3s/adminer",
                      f"K3s/{component}", "K3s/ingress"]:
        for k3s_file in sorted(glob.glob(f"{directory}/*.yaml")):
            apply_manifest(k3s_file)
   

def rollout_status(component):
    run_script(["kubectl", "rollout", "status",
                f"deployment/{PREFIX}volunti-{component}",
                "-n", NAMESPACE, "--timeout=120s"])

def main():
    if not REGISTRY or not TAG:
        print("Please set a REGISTRY_IMAGE and a CI_COMMIT_SHORT_SHA", file=sys.stderr)
        sys.exit(1)
    print(f"Deploying {COMPONENT}:{NAMESPACE}:{TAG}")
    apply_manifests(COMPONENT)
    rollout_status(COMPONENT)
    print(f"Succesfully deployed {COMPONENT}")

if __name__ == "__main__":
    main()
