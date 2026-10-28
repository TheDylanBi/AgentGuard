# 运行全部正常任务

本地AgentDojo v1.2.2公开正常任务共97项：workspace 40，travel 20，
banking 16，slack 21。之前的`-AllTasks`只覆盖当前suite，默认workspace。
攻击目标和攻击组合不计入这97项。

在已激活agentdojo环境的PowerShell中：

```powershell
Set-Location 'F:\Code\MLLM Agent'
# 不调用模型，只检查四套工具清单、Schema、Node/pi安装。
& '.\.local-qwen\run-qwen.ps1' -AllSuites -IntentFormat review -Check
# 使用安全策略，顺序运行四个suite的全部97项无攻击任务。
& '.\.local-qwen\run-qwen.ps1' -AllSuites -IntentFormat review
# 对照：同一工具声明和执行器，不启用任务安全策略。
& '.\.local-qwen\run-qwen.ps1' -AllSuites -Mode baseline
```

复用当前脚本中的模型/API配置，不需要重新输入密钥。
review仍为实验模式；新套件的能力/Schema声明是接入基础，不保证每个任务
都有完整的参数来源或资源绑定支持。不因为扩展测试范围而取消金融、数据流等检查。
套件中的银行交易等操作仅作用于官方模拟环境。

单独运行一个suite的全部正常任务：

```powershell
& '.\.local-qwen\run-qwen.ps1' -Suite travel -AllTasks -IntentFormat review
& '.\.local-qwen\run-qwen.ps1' -Suite banking -AllTasks -IntentFormat review
& '.\.local-qwen\run-qwen.ps1' -Suite slack -AllTasks -IntentFormat review
```

全suite运行不能附加Attack、InjectionTask、UserTask或Suite筛选。
默认继续记录任务级模型错误；连续服务错误仍可让当前suite提前终止，随后
保留该suite记录并处理其他suite，不伪造剩余任务评分。Ctrl+C会写出当前可用汇总。

全局输出为`results/agentdojo_pi_all_clean_<时间戳>/summary.json`；每个suite
各有子目录和原始summary。全局记录成功数/97、已评分完成率、评分覆盖率、
模型错误和未处理数。它不会把四个suite的百分比简单平均，也不会把无攻击
security=true解释成防御成功。`plan.json`记录实际加载版本的任务数量。

工具声明按本地真实函数及Schema冻结。可复用工具只有Schema相同才复用声明；
金融转账保留financial_transfer效应；旅行预订保留持久化及隐式读取个人信息。
本地上游reserve_car_rental实现将结束时间设为开始时间，其行为已注明，
未修改基准代码或为特定任务改写结果。

新增入口通过四suite配置预检与离线执行/汇总测试，尚未进行97项真实模型全量运行。
