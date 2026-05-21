#!/bin/bash

echo "🐍 Setting up isolated Python environment for Suburban-SOC..."

# 1. Check if the venv module is available (sometimes requires a manual apt install on fresh systems)
if ! python3 -c "import venv" &> /dev/null; then
    echo "❌ Error: python3-venv is not installed."
    echo "Run 'sudo apt install python3-venv' first, then rerun this script."
    exit 1
fi

# 2. Create a virtual environment named '.venv' in the current directory
python3 -m venv .venv

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Upgrade pip inside the sandbox
echo "🔄 Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# 5. Install PyYAML (and any other tools you need)
echo "📦 Installing PyYAML..."
pip install pyyaml

echo "✅ Environment configured successfully!"
echo "--------------------------------------------------------"
echo "⚠️  IMPORTANT: To use this environment, you must run this command in your terminal first:"
echo "    source .venv/bin/activate"
echo "--------------------------------------------------------"
