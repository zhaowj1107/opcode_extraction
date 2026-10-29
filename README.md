# AndroZoo APK 下载 + Opcode 提取（AndroType opcode 3-gram 词表重算）

这个 repo 用来分工下载 AndroZoo 上的 7,177 个 APK，并为每个 APK 生成 17 类 opcode 符号序列（`<SHA256>.cat`）。结果用来重新统计 AndroType 训练集的 opcode 3-gram 词表大小（即原 TS-Base 2,750 列之外还有多少个 3-gram，记为 *k*）。

每个 worker 每次只处理一个 APK：下载、校验 SHA-256、apktool/baksmali 反汇编、生成 `.cat`，然后**立即删除 APK**。最终只保留 `.cat` 文件和状态 CSV，所以不需要几百 GB 的磁盘。

## 哈希列表

| 文件 | 数量 | 约总大小 | 内容 |
|---|---:|---:|---|
| `hashes/p1_new_benign.txt` | 3,510 | 129.5 GB | 新增良性 APK（优先） |
| `hashes/p1_new_malware.txt` | 29 | 0.7 GB | 新增恶意 APK（优先） |
| `hashes/p2_tsbasetest_benign.txt` | 3,600 | 158.9 GB | 原 TS-Base test 中的良性 APK |
| `hashes/p2_tsbasetest_malware.txt` | 38 | 1.8 GB | 原 TS-Base test 中的恶意 APK |

请先做 **p1**（4,665 个真正新增的 APK 中，需要从 AndroZoo 下载的部分），再做 p2。

## 环境要求

- Python 3.9+，Java 8+（`java` 要在 PATH 上）
- 推荐 Linux 或 macOS；Windows 也可以（已处理超长路径）
- 磁盘：大约 20 GB 空闲即可（只有正在处理的几个 APK 和反汇编临时目录在盘上）
- **一个你自己的 AndroZoo API key**（在 <https://androzoo.uni.lu/access> 申请）。AndroZoo 的 key 是个人的，不要共用，也不要提交到 git。

## ⚠️ 安全须知

- 列表里有 **67 个恶意 APK**（`*_malware.txt`）。流程只做静态反汇编，不会安装或运行 APK，处理完立即删除。
- 尽量在 VM、服务器或 cluster 上运行，不要在个人主力机上运行。
- Windows Defender 等杀毒软件可能会隔离个别恶意 APK，这些会记为 `failed`，属正常现象。**不要为此关闭杀毒软件或添加排除项**，把失败的哈希交回即可。

## 步骤

```bash
git clone <this repo> && cd androzoo-opcode-extraction
python -m pip install -r requirements.txt
python setup_tools.py            # 下载 apktool 2.9.3 和 baksmali 2.5.2，并校验 SHA-256
```

把你的 AndroZoo key 单独写一行存进 `api_key.txt`（已被 `.gitignore` 忽略）：

```bash
echo "YOUR_ANDROZOO_KEY" > api_key.txt
```

先跑 2 个 APK 测试：

```bash
python run_pipeline.py --hash-list hashes/p1_new_benign.txt hashes/p1_new_malware.txt --key-file api_key.txt --limit 2
```

正式运行。多人分工时用 `--shard i/n`，例如 4 个人分别用 `1/4`、`2/4`、`3/4`、`4/4`：

```bash
python run_pipeline.py --hash-list hashes/p1_new_benign.txt hashes/p1_new_malware.txt --key-file api_key.txt --shard 1/4 --workers 4
```

> 分片是按传入列表**合并后的顺序**切分的，所以所有人必须传入**相同的文件，并且顺序相同**。

- 中断后直接重跑同一条命令即可续跑：已完成的会跳过，`failed` 的会重试。
- 如果 key 失效，脚本会立即停止并提示 `AndroZoo rejected the API key`。
- p1 完成后，换成 `hashes/p2_tsbasetest_benign.txt hashes/p2_tsbasetest_malware.txt` 再跑一遍，分片方式相同。

## 检查并交回结果

```bash
python check_results.py --hash-list hashes/p1_new_benign.txt hashes/p1_new_malware.txt --shard 1/4 --pack
```

`check_results.py` 会输出以下内容：

- 完成数、缺失数，以及缺失样本最后一次的失败原因
- `.cat` 自检结果：正常文件应包含 `X`，且**不能包含 `N`**。出现 `N` 说明用错了提取器。
- 缺失哈希列表：`work/missing_shard*.txt`
- 加 `--pack` 时会生成 `work/cats_<主机名>_shard<i>of<n>.zip`，把这个 zip 交回即可。

## 输出格式

- `work/cats/<SHA256>.cat`：一行文本，内容是 17 类符号序列，例如 `MVMOVI...`
- `work/logs/status_shard<i>of<n>.csv`：每个 APK 的状态，可能是 `ok`、`not_found`、`failed` 或 `auth_error`

## 为什么必须用这套提取器

TS-Base 原始的 2,750 列由 apktool/smali 路径（`opcode_extraction_17cat.py`，原样拷贝自 MOSAIC 主 repo）生成。这条路径会跳过 `nop`，因此永远不会产生 `N`，也不会产生 `F`。androguard 路径会为 `nop` 输出 `N`，生成的 3-gram 是提取器差异造成的伪新增。

所以这里**只用 apktool/baksmali**。`run_pipeline.py` 原样复用 `opcode_extraction_17cat.py` 的 smali 解析和符号映射，只做了两处与结果无关的改动：

1. 第一次调用 apktool 时加 `-r`（不解码资源），smali 输出不变，速度更快。
2. 去掉只适用于 POSIX shell 的 `JAVA_OPTS=` 前缀，改由 wrapper 传入 `-Xmx4g`。
