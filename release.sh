#!/usr/bin/env bash
set -euo pipefail
# release.sh — 构建 + GitHub Release 一键发布
# 用法: ./release.sh v1.3.1 "修复了 xxx 问题"

VERSION="${1:-}"
NOTES="${2:-}"

if [ -z "$VERSION" ]; then
    echo "用法: ./release.sh <版本号> [更新说明]"
    echo "示例: ./release.sh v1.3.1 \"修复 attach 模式 PID 解析\""
    exit 1
fi

cd "$(dirname "$0")"

# 更新版本号
echo "$VERSION" | sed 's/^v//' | read -r VER
sed -i '' "s/^version = .*/version = \"$VER\"/" pyproject.toml
sed -i '' "s/^__version__ = .*/__version__ = \"$VER\"/" xfqtrace/__init__.py

# 构建
echo ">>> 构建 $VERSION ..."
rm -rf dist build *.egg-info
python3 -m build

# 打 tag
git add -A
git commit -m "release: $VERSION"
git tag "$VERSION"

# 发布到 GitHub
echo ">>> 创建 GitHub Release ..."
gh release create "$VERSION" dist/* --title "$VERSION" --notes "${NOTES:-release $VERSION}"

# 推送
git push && git push --tags

echo "[+] $VERSION 发布完成"
echo "    https://github.com/Orangechenx/xfqtrace-tools/releases/tag/$VERSION"
