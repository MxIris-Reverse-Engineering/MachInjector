# Evolution 提案索引

- **项目类型**: 库（源码分发）

SPM library product，使用方以源码依赖并重新编译，未开启 library evolution，
也不以 `binaryTarget` 分发。

**「ABI 兼容性」一节填「不适用 —— 本库以 SPM 源码分发，使用方每次重新编译」即可；
「源码兼容性」一节必填。**

本库有一条特有的注意事项：**注入链路的正确性依赖平台细节，提案的「前期调研」一节必须交代
在什么架构、什么系统版本上验证过**。arm64e 的指针签名、chained fixups 的格式、沙盒策略
都会随系统演进，「在我机器上能跑」不构成结论。相关背景见
[`Design/PACHandbookForRemap.md`](../Design/PACHandbookForRemap.md)。

提案格式与流程见全局 `CLAUDE.md` 的「Evolution 提案制」一节，用 `/evolution <描述>` 创建。

## 提案

| # | 标题 | 状态 |
|---|------|------|
| [0001](0001-restore-payload-writable-segments-before-fixups.md) | Remap 前把 payload 可写段恢复为文件原始内容 | Implemented |
| [0002](0002-classify-and-publish-injection-error-codes.md) | 把注入失败分类成可判定的错误码，并公开三个 domain 的枚举 | Implemented |

`Design/` 下的架构文档是提案制确立前的产物，见[上级索引](../README.md)，保持原样不迁移。
