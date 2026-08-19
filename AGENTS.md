dae 是一个基于 Linux eBPF 的高性能透明代理解决方案。

本项目从 [daeuniverse/dae/tree/legacy](https://github.com/daeuniverse/dae/tree/legacy) fork 而来，fork 基线 commit 为：

```
39831d5d24a129ce8c53258e54cfe6cde1502529
```

该 commit 之后的所有改动均为本仓库的修改。

版权声明规则：

- 修改带版权头的上游源码时，保留原版权声明，并追加 `Copyright (c) 2026, 9bingyin`。
- 本 fork 新增且需要版权头的源码只使用 `Copyright (c) 2026, 9bingyin`，不要使用 daeuniverse 的版权声明。
- `.envrc`、Nix 配置、锁文件、CI workflow 和维护脚本默认不新增本 fork 的文件级版权头；原有上游或第三方声明仍需保留。
- 第三方代码保留其原许可证和版权声明。
