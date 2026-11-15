
from pathlib import Path
from urllib.parse import quote

# Repository root
ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

EXCLUDED = {
    ".git", ".github", "__pycache__",
    ".venv", "venv", "node_modules",
    ".DS_Store"
}

def file_link(path):
    relative = path.relative_to(ROOT).as_posix()
    url = quote(relative, safe="/-._()")
    return f"[View File]({url})"

def generate():
    lines = [
        "# Information Security Lab 2026 – JNTUH",
        "",
        "**M.Tech | Cyber Forensics and Information Security**",
        "",
        "## About",
        "",
        "This repository contains practical implementations "
        "of cryptographic algorithms, cipher techniques, "
        "and information security experiments completed at JNTUH.",
        "",
        "## Laboratory Experiments",
        ""
    ]

    folders = sorted(
        [
            p for p in ROOT.iterdir()
            if p.is_dir() and p.name not in EXCLUDED
        ],
        key=lambda p: p.name.lower()
    )

    total = 0

    for number, folder in enumerate(folders, 1):
        files = sorted(
            [
                p for p in folder.rglob("*")
                if p.is_file()
                and not any(
                    part in EXCLUDED
                    for part in p.relative_to(ROOT).parts
                )
            ],
            key=lambda p: p.as_posix().lower()
        )

        if not files:
            continue

        lines.extend([
            f"### {number}. {folder.name}",
            "",
            "| File Name | Link |",
            "|---|---|"
        ])

        for file in files:
            name = file.relative_to(folder).as_posix()
            name = name.replace("|", "\\|")
            lines.append(
                f"| {name} | {file_link(file)} |"
            )
            total += 1

        lines.append("")

    lines.extend([
        "---",
        "",
        f"**Total Files:** {total}",
        "",
        "*README automatically generated using GitHub Actions.*"
    ])

    README.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print(f"README generated successfully: {total} files.")

if __name__ == "__main__":
    generate()
