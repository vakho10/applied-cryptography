import hashlib
import json
import sys


def compute_hashes(filename):
    hashes = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),
        "md5": hashlib.md5()
    }
    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def save_hashes(filename, hash_dict):
    with open(filename, 'w') as f:
        json.dump(hash_dict, f, indent=4)


def load_hashes(filename):
    with open(filename, 'r') as f:
        return json.load(f)


def check_integrity(file_to_check, stored_hashes):
    current = compute_hashes(file_to_check)
    status = {}
    for algo in stored_hashes:
        match = current[algo] == stored_hashes[algo]
        status[algo] = "PASS" if match else "FAIL"
    return status


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python task5.py generate original.txt")
        print("  python task5.py check tampered.txt")
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]

    if mode == "generate":
        hashes = compute_hashes(filename)
        save_hashes("hashes.json", hashes)
        print(f"Hashes saved to hashes.json for {filename}")
    elif mode == "check":
        stored = load_hashes("hashes.json")
        result = check_integrity(filename, stored)
        with open("integrity_check_output.txt", "w") as f:
            for algo, status in result.items():
                line = f"{algo.upper()}: {status}"
                print(line)
                f.write(line + "\n")
    else:
        print("Invalid mode. Use 'generate' or 'check'.")
