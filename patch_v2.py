
# patch goreleaser
with open("go/.goreleaser.yaml", "r") as f:
    content = f.read()

content = content.replace("  github:\n    draft: true\n    prerelease: auto", "  draft: true\n  prerelease: auto")

with open("go/.goreleaser.yaml", "w") as f:
    f.write(content)

# patch scorecard
with open(".github/workflows/scorecard.yml", "r") as f:
    scorecard = f.read()

scorecard = scorecard.replace("ossf/scorecard-action@v2", "ossf/scorecard-action@main")

with open(".github/workflows/scorecard.yml", "w") as f:
    f.write(scorecard)
