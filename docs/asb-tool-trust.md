# ASB 工具来源、首次授权与失败诊断

严格部署要求同时通过独立工具契约验证和本次任务授权。默认保留 ASB 有限来源可见性实验，不从 normal/attacker 标签生成可信名单。启用严格模式是不同信任假设，须单独报告，不能把全拒绝当作防御收益。

## v2 独立工具契约

由可信运维方审阅实现并填写契约，然后给原 ASB 命令添加：

```powershell
--tool-contracts '你的独立工具契约.json' --require-tool-contracts
```

严格契约模式会在任何模型调用前验证契约格式、目录和运行时绑定，并在运行时拒绝
任何未注册、旧版或实例不匹配的工具。覆盖清单写入 `tool-contract-coverage.json`；
缺失工具会记录为未注册并在调用时拒绝，多余声明会报告但不会自动获得权限。这使
注入评测可以继续执行正常工具，同时让新注入的未注册工具在执行边界被阻止。

对固定部署目录或 clean 运行，如果要求本次所选目录必须全部被完整 v2 契约覆盖，
再显式增加：

```powershell
--require-complete-tool-contract-coverage
```

该开关发现任何未注册工具都会在模型调用前停止。不要把这种配置拒绝记成攻击成功率
为零；它适合部署完整性检查，不适合需要逐例得到官方分数的工具注入评测。

若部署方提供了独立公钥，可进一步验证分离签名：

```powershell
--tool-contracts '工具契约.json' `
--tool-contract-signature '工具契约.sig' `
--tool-contract-public-key '可信发布方公钥.pem' `
--require-tool-contracts --require-signed-tool-contracts
```

契约经人工审阅后，可用已在工作区外独立配置的密钥签名；该工具不会创建信任根，
也不会覆盖已有签名：

```powershell
& '.\tmp\asb-venv\Scripts\python.exe' -X utf8 -B -m adapters.asb.contract_sign `
  --contract '工具契约.json' --private-key '独立保管的私钥.pem' `
  --public-key '可信发布方公钥.pem' --output '工具契约.sig'
```

程序会先确认私钥与独立公钥匹配，再原子写入签名。私钥、公钥和契约放在同一
不可信目录仍不构成独立信任；生产环境应由部署系统只读注入公钥，并限制私钥访问。

签名格式是 `ed25519:<base64>`，签署对象是 JSON 解析后按键排序、无多余空白的
UTF-8 序列化。公钥必须经独立渠道配置；与契约放在同一不可信来源只能证明两份
文件自洽，不能证明发布方身份。结果保存签名、公钥、验证状态和公钥指纹，并在归档
后重新验证，避免检查与执行之间替换文件。签名证明来源与完整性，仍不证明能力声明
语义正确，也不授予某次任务权限。

结构示意；占位哈希不能执行，也不是根据 ASB 生成的许可名单：

```json
{
  "version": 2,
  "tools": {
    "report_reader": {
      "issuer": "可信运维方",
      "catalog_hash": "sha256:<64位小写十六进制>",
      "runtime_hash": "sha256:<64位小写十六进制>",
      "operation": "read",
      "effects": ["read"],
      "provenance": {
        "source": "经独立审阅的实现或发布来源",
        "review_reference": "审阅记录的位置与版本"
      },
      "implementation": {
        "version": "经审阅的实现版本",
        "entrypoint": "package.module.Class.run",
        "configuration_hash": "sha256:<64位小写十六进制>"
      },
      "capability": {
        "purpose": "读取指定报告；不会交易或修改数据",
        "resource_type": "report",
        "reads": ["经审阅的报告范围"],
        "writes": [],
        "data_flows": [{"source": "报告", "destination": "任务内工具观察"}]
      }
    }
  }
}
```

- `catalog_hash` 是 `object_hash({'tool': 工具名, 'description': 目录原文})`。
- `runtime_hash` 是 `sha256:` 加本次 `pyopenagi/tools/simulated_tool.py` 文件 SHA-256。
- `implementation.entrypoint` 和 `configuration_hash` 由 `implementation_identity(instance)` 计算。
  后者绑定实例全部静态字段，包括模拟工具配置的固定返回行为；原文不传入审查模型。
- 版本、来源和能力说明是运维方的可信声明。程序检查完整性及绑定，不能证明声明诚实、来源权威或实现语义正确。
- v1 仍可读取，但不满足严格模式；不能自动编造缺失字段。
- 未声明、旧契约、实例不匹配分别记录为 `tool.provenance_required`、`tool.contract_upgrade_required`、`tool.contract_pin_mismatch`。
- 首次模型审查前核验，允许后再次核验。任务审查仍可拒绝可信工具；调用、契约、状态变化使原授权失效。
- 操作类别与效果分别表达。例如查询可包含 `network_egress`；复合读取可声明写入效果，但必须写明写入范围。通信须声明数据流。这些效果仍须经过授权审查，不因 `read` 标签自动放行。

这不是恶意 Python 沙箱或自动语义验证。ASB 无实际执行参数，无法把公司、账户、收件人或网络目的地约束落实到真实财务系统；资源和流向是声明上界，不能称为已观测效果或生产数据流控制。真实有状态工具需要区分配置和运行状态的适配器。

## portfolio_manager 的可确认事实

本地 `F:/Datasets/ASB/pyopenagi/tools/simulated_tool.py` 中，`SimulatedTool.run(params=None)` 只返回 `self.expected_achivement`。目录声称支持资产配置分析、风险评估、表现跟踪；实现既没有这些分析，也没有真实交易、调仓、账户读取或子操作参数。

因此没有依据补出“季度分析必需且只读”的独立契约。官方评分要求全部正常工具的成功标记，这不能成为用户授权或强制恢复目标。本轮不改该工具的允许结论，不编造公司或季度。真实工具应从经过审阅的实现区分分析与交易，并为后者提供明确目标和参数。

## 案例诊断与实验边界

每个案例的 `diagnostics.json` 分成官方标记覆盖、授权边界、用户信息候选和交付证据
四个轴。拒绝进一步区分来源未验证、绑定不匹配、任务范围、目标、额外效果和证据
不足。`calls.json` 分开记录工具可信性、硬检查与任务授权。

评分后才读取原生正常工具标记，报告缺失标记、未尝试工具和“评分与语义分歧候选”。
`official_marker_coverage_pass` 只表示原评分成功，不改写为已验证交付。任务要求的
checkpoint 状态也明确标为模型意见；即使有执行票据，仍不会写成独立完成证明。
这些诊断不送回授权器，不改官方分数。澄清文本匹配只是人工复核线索，不能证明
环境无法提供信息；有限原因码也不能完整证明拒绝因果。

`code_snapshot/` 保存本次策略与适配器源码，按 `policy-source-hashes.json` 验证，不复制凭据。比较包含契约指纹和是否要求契约，防止混用信任假设。恢复默认仍为 `native`，不增加重规划次数。

离线测试包括未验证名称/描述变体、配置/入口替换、审查期间变更、撤销和任务拒绝，也明确测试：错误的可信运维声明叠加错误模型判断，仍可能执行有害动作。测试证明执行门禁行为，不证明语义攻击识别率。没有独立 ASB 契约时，只能报告有限来源条件下的效果。

## 审查快照与只审查重放

每例 `review-inputs.json` 保存准备发送的完整提示、原始请求、证据、输出 Schema、已解析的生成设置及模型/接口指纹。快照在传输前生成；是否收到响应仍须结合 `reviews.json`，不能把快照存在当作服务调用成功的证明。文件含任务数据，不保存服务凭据。

使用相同审查服务环境进行重放：

```powershell
& '.\tmp\asb-venv\Scripts\python.exe' -X utf8 -B -m adapters.asb.review_replay `
  --input '某次结果/某个案例/review-inputs.json' --index 0 --repeats 5 `
  --output 'results/你的独立重放结果.json'
```

重放使用保存的请求，不重新规划、不执行工具、不使用在线拒绝缓存，也不把某次 allow 消费成权限。保留每次结果；协议错误不重试为放行，401/402/403 停止并保留未尝试分母。代码、模型或接口不同时拒绝静默对比。哈希是完整性检查，不是外部文件的可信签名。

重放输出的 `decision_disagreement` 只比较这批重放样本。还须按请求 ID 关联原始 `reviews.json`：原调用为 needs_evidence、重放全为 allow 时，即使该字段为 false，也存在原调用与重放不一致，不能宣称审查稳定。

`--authorization-profile scope` 是可选实验准则：区分“用户已允许的辅助校验”和“是否最优或必需”。默认 `standard` 不变；显式资源、接收方、效果和工具限制始终保留。准则不新增模型输出字段，不使用自报置信度，也不把相关性变为授权。

`adapters.asb.review_eval` 固定 12 个能力/效果明确的独立规范案例。预期标签仅用于评分，未发送给模型；工具等价变体、网络查询、复合写入、外传、资源越界、注入和信息不足均有覆盖。这是合成测试，不是 ASB 标准结果，也不能替代真实工具的独立审阅。
