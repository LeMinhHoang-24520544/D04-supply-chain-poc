import os
import json
import shutil
import random
import string
import base64

# Configuration
SOURCE_DIR = './packages'
OUTPUT_DIR = './generated_packages'
NUM_PACKAGES = 100

templates = {
    'benign': 'uit-benign',
    'lifecycle': 'uit-marker-lifecycle',
    'confusion': 'uit-core-auth'
}

# Safe mock payloads
# Simulate malicious behavior safely
LIFECYCLE_MOCKS = [
    "echo '[MOCK] Simulating external request...' > /dev/null",
    "node -e \"console.log(Buffer.from('VGhpcyBpcyBhIHNhZmUgbW9jayBwYXlsb2Fk', 'base64').toString())\"", 
    "cat package.json | grep name > /dev/null",
    "mkdir -p /tmp/test_dir && echo 'mock' > /tmp/test_dir/test.txt"
]

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_data():
    print(f"Generating {NUM_PACKAGES} mock packages...")
    
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)

    for i in range(1, NUM_PACKAGES + 1):
        # Set distribution ratio
        pkg_type = random.choices(['benign', 'lifecycle', 'confusion'], weights=[0.6, 0.2, 0.2])[0]
        src_path = os.path.join(SOURCE_DIR, templates[pkg_type])
        new_pkg_name = f"uit-dataset-pkg-{i:03d}"
        dest_path = os.path.join(OUTPUT_DIR, new_pkg_name)

        shutil.copytree(src_path, dest_path)
        
        pkg_json_path = os.path.join(dest_path, 'package.json')
        with open(pkg_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Randomize metadata
        data['name'] = new_pkg_name
        data['description'] = f"Package {random_string(5)} for internal use."
        data['author'] = random.choice(["Dev Team", "Admin", random_string(8), ""])
        data['license'] = random.choice(["MIT", "ISC", "GPL-3.0"])

        # Process package mutations
        if pkg_type == 'lifecycle':
            data['version'] = f"1.{random.randint(0, 5)}.{random.randint(1, 20)}"
            if 'scripts' not in data:
                data['scripts'] = {}
            
            # Inject multiple hooks
            hooks = random.sample(['preinstall', 'install', 'postinstall', 'preuninstall'], k=random.randint(1, 2))
            for hook in hooks:
                data['scripts'][hook] = random.choice(LIFECYCLE_MOCKS)
                
            # Add normal scripts for noise
            data['scripts']['test'] = "echo 'Error: no test specified' && exit 1"

        elif pkg_type == 'confusion':
            # Set unusually high version
            data['version'] = f"{random.choice([99, 999, 100])}.{random.randint(0,9)}.{random.randint(1,99)}"
            
            # Create obfuscated but safe js file
            safe_js = f"console.log('Simulating logic for {new_pkg_name}');"
            encoded_js = base64.b64encode(safe_js.encode()).decode()
            obfuscated_code = f"eval(Buffer.from('{encoded_js}', 'base64').toString('utf-8'));"
            
            with open(os.path.join(dest_path, 'index.js'), 'w', encoding='utf-8') as js_file:
                js_file.write(obfuscated_code)
            data['main'] = 'index.js'
            
            # Add fake dependencies
            data['dependencies'] = { f"fake-dep-{random_string(4).lower()}": "^1.0.0" }

        else: 
            # Clean package
            data['version'] = f"{random.randint(1,4)}.{random.randint(0,9)}.{random.randint(0,9)}"
            if 'scripts' in data:
                # Remove suspicious hooks
                for hook in ['preinstall', 'install', 'postinstall']:
                    data['scripts'].pop(hook, None)
            
            # Add normal index file randomly
            if random.random() > 0.5:
                with open(os.path.join(dest_path, 'index.js'), 'w', encoding='utf-8') as js_file:
                    js_file.write("module.exports = function() { return 'Hello World'; };")
                data['main'] = 'index.js'

        # Save package data
        with open(pkg_json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f"Created {new_pkg_name} ({pkg_type.upper()} - v{data['version']})")

if __name__ == "__main__":
    generate_data()
    print(f"\nFinished generating {NUM_PACKAGES} packages in {OUTPUT_DIR}")