import os
import re

wf_dir = ".github/workflows"

for file in os.listdir(wf_dir):
    if not file.endswith(".yml"):
        continue
    path = os.path.join(wf_dir, file)
    with open(path, "r") as f:
        content = f.read()

    # checkout
    content = re.sub(r'actions/checkout@[^\s]+(\s+#.*)?', 'actions/checkout@v7', content)
    # setup-python
    content = re.sub(r'actions/setup-python@[^\s]+(\s+#.*)?', 'actions/setup-python@v6', content)
    # upload-artifact
    content = re.sub(r'actions/upload-artifact@[^\s]+(\s+#.*)?', 'actions/upload-artifact@v7', content)
    # codeql-action
    content = re.sub(r'github/codeql-action/([^@]+)@[^\s]+(\s+#.*)?', r'github/codeql-action/\1@v4', content)

    # fix review-gate paths and installs
    if file == "review-gate.yml":
        content = content.replace('pip install pytest pytest-cov\n          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n          if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi', 'pip install -e ".[dev,server]"')
        content = content.replace('pip install mypy\n          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n          if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi', 'pip install -e ".[dev,server]"')
        content = content.replace('pip install pytest pytest-cov coverage\n          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n          if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi', 'pip install -e ".[dev,server]"')
        content = content.replace('pip install bandit', 'pip install -e ".[dev,server]"')
        content = content.replace('pip install pip-audit', 'pip install -e ".[dev,server]"')
        
        # fix missing module
        content = content.replace('pytest -ra --strict-markers', 'pytest -ra --strict-markers tests/')
        content = content.replace('--cov=vault', '--cov=rgt_vault')
        content = content.replace('mypy vault/', 'mypy rgt_vault/')
        content = content.replace('bandit -r vault/', 'bandit -r rgt_vault/')

    with open(path, "w") as f:
        f.write(content)
