# HymoFS LKM for Hybrid Mount

本项目是专为 **Hybrid Mount** 项目定制的 HymoFS 内核模块（LKM）分支。
HymoFS 是一款轻量级的内核层文件系统路径重定向与隐藏模块。本仓库作为独立的编译构件，专门负责通过 DDK 体系构建兼容各 GKI 版本的 `hymofs_lkm.ko` 文件，供 Hybrid Mount 核心调用。

## License

Author's work under Apache-2.0; when used as a kernel module (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.

## 鸣谢

[@Anan](https://github.com/Anatdx) 原始HymoFS仓库
