# 目标目录（可用环境变量覆盖：TARGET_DIR=/mnt/d/... just sync）
TARGET_DIR := env_var_or_default(""TARGET_DIR", "/mnt/d/Code/Rust/recordit-mirror"/"0

# 使用 bash 并开启严格模式
set shell := ["bash", "-ueo", "pipefail", "-c"]

default:
  @just --list

# 实际同步（镜像）
sync:
  # 确认在 Git 仓库内
  git rev-parse --is-inside-work-tree >/dev/null

  # 创建目标目录
  mkdir -p {{TARGET_DIR}}

  # 只根据 Git 追踪的文件同步（包含工作区修改），递归到子模块
  # --delete: 让目标成为镜像；删除目标里不在清单中的多余文件
  git ls-files -z --recurse-submodules \
    | rsync -a --from0 --files-from=- --relative --progress ./ {{TARGET_DIR}}

# 试运行（不改动目标），先看看将要发生什么
sync-dry:
  git rev-parse --is-inside-work-tree >/dev/null
  mkdir -p {{TARGET_DIR}}
  git ls-files -z --recurse-submodules \
    | rsync -a -n  --from0 --files-from=- --relative --progress ./ {{TARGET_DIR}}

# 仅把会受影响的路径打印出来（调试用）
sync-list:
  git ls-files --recurse-submodules

