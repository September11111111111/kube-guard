# KubeGuard

一个基于 **Kubebuilder** 构建的 Kubernetes Operator：  
它会**定期查询 Prometheus 指标**，根据配置的**阈值表达式**判断服务是否异常，并在满足条件时对目标工作负载执行**自动重启**，实现基础的自愈能力。

---

## 环境依赖与安装

在运行 KubeGuard 之前，建议先准备以下环境：

- Go
- Docker
- kubectl
- kind（或其他 Kubernetes 集群）
- make
- Kubebuilder 相关工具
- Prometheus（用于提供指标查询能力）

---

## 项目简介

在 Kubernetes 集群中，很多服务虽然已经具备副本机制和探针机制，但仍然会出现这类问题：

- Pod 处于 Running，但业务指标已经异常
- 服务没有彻底挂掉，因此不会被探针自动拉起
- 人工排查和手动重启成本高，恢复速度慢

**KubeGuard** 解决的是这一类“**业务层指标异常，但基础设施层还没完全失效**”的问题。

它通过以下流程工作：

1. 周期性读取 Prometheus 指标
2. 将查询结果与阈值表达式比较
3. 判断是否需要触发动作
4. 在冷却时间外，对目标 Deployment 执行一次“重启”
5. 把本次检测值、动作结果和状态条件写回到 CR Status 中

---

## 核心特性

- 基于 Kubebuilder 开发，符合 Kubernetes Operator 模式
- 支持 **Prometheus 即时查询（Instant Query）**
- 支持通过字符串配置阈值表达式，例如：
  - `> 0`
  - `>= 80`
  - `< 10`
  - `!= 1`
- 支持配置检测周期 `EvaluateEverySeconds`
- 支持配置冷却时间 `CooldownSeconds`
- 支持将最近一次检测值写回 `status.lastValue`
- 支持将最近一次动作时间写回 `status.lastActionTime`
- 支持维护 Kubernetes 标准 `status.conditions`
- 当前动作类型：**重启目标 Deployment**

---

## 当前实现范围

当前版本聚焦于最小可用闭环，已实现：

- 目标类型：`Deployment`
- 动作类型：`restart`
- 自愈方式：给目标 Deployment 的 Pod Template 注入/更新注解  
  `kubeguard/restartedAt=<RFC3339时间戳>`
- 通过修改 Pod Template 触发 Kubernetes 滚动重建

暂未实现但适合作为后续扩展方向：

- 支持 StatefulSet / DaemonSet
- 支持多种动作（scale / rollback / patch）
- 支持更复杂的规则组合
- 支持事件记录与告警联动
- 支持多指标联合判断

---

## 工作流程

### 1. 读取 GuardPolicy
Controller 首先读取用户定义的 `GuardPolicy` 资源。

### 2. 解析调度参数
如果用户未配置或配置非法，则使用默认值：

- `EvaluateEverySeconds <= 0` 时，默认 `30s`
- `CooldownSeconds <= 0` 时，默认 `180s`

### 3. 查询 Prometheus
向：

`<prometheusURL>/api/v1/query?query=<promql>`

发起即时查询，解析返回值。

### 4. 阈值判断
将返回值与阈值表达式比较，例如：

- `> 0`
- `>= 90`
- `< 5`

### 5. 冷却判断
若上次动作时间距离当前还未超过冷却时间，则本次跳过动作。

### 6. 触发重启
若满足阈值并且不在冷却期内，则对目标 Deployment 进行 patch，触发滚动重启。

### 7. 写回状态
将以下信息写入 `status`：

- `lastValue`
- `lastAction`
- `lastActionTime`
- `conditions`

---

## 自定义资源设计

### GuardPolicySpec

```yaml
spec:
  prometheusURL: "http://prometheus-k8s.monitoring.svc:9090"
  query: 'sum(rate(http_requests_total[1m]))'
  threshold: "> 100"
  evaluateEverySeconds: 30
  cooldownSeconds: 180
  targetRef:
    namespace: default
    kind: Deployment
    name: my-app
```

---

## 最小恢复实验

在本地 kind 集群上，使用测试 Deployment 与 mock Prometheus 指标源进行了最小闭环验证。

实验配置：

- `evaluateEverySeconds: 5`
- `cooldownSeconds: 60`
- `threshold: == 0`
- target: `Deployment/demo-app`

实验中，mock 指标在启动 20 秒后由正常值 `1` 切换为异常值 `0`。控制器在检测到阈值命中后，成功触发目标 Deployment 的滚动重启，并在冷却窗口内跳过重复动作。

一次实验测得：

- 检测延迟：约 **1.0s**
- 动作落地耗时：**小于 1s**
- 端到端自动恢复触发耗时：约 **1.0s**