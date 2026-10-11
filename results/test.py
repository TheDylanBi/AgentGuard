# -*- coding: utf-8 -*-
"""
复现参考图中的三维散点图：
- 纯白背景
- 蓝色坐标轴
- 绿色散点集群（分布在左前方）
- 红色散点集群（分布在右后方）
两组点在三维特征空间中呈现聚类分离。
"""
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401

rng = np.random.default_rng(42)


def cluster(center, n, spread):
    return rng.normal(loc=center, scale=spread, size=(n, 3))


# 绿色集群：分布在左侧，X 取小值，Y/Z 中等偏上
green = cluster([0.25, 0.55, 0.60], 90, 0.16)
# 红色集群：分布在右侧，X 取大值，Y/Z 中等偏下
red = cluster([0.78, 0.42, 0.32], 90, 0.16)

fig = plt.figure(figsize=(7, 7), facecolor="white")
ax = fig.add_subplot(111, projection="3d")
ax.set_facecolor("white")

# 蓝色坐标轴
for axis in (ax.xaxis, ax.yaxis, ax.zaxis):
    axis.set_pane_color((1.0, 1.0, 1.0, 1.0))
    axis.line.set_color("tab:blue")
    axis.line.set_linewidth(1.8)
    axis.set_tick_params(color="tab:blue", labelcolor="tab:blue")
    axis.pane.set_edgecolor("tab:blue")

ax.scatter(green[:, 0], green[:, 1], green[:, 2],
           color="tab:green", s=28, alpha=0.75, depthshade=False,
           label="安全状态")
ax.scatter(red[:, 0], red[:, 1], red[:, 2],
           color="tab:red", s=28, alpha=0.75, depthshade=False,
           label="风险状态")

ax.set_xlabel("X")
ax.set_ylabel("Y")
ax.set_zlabel("Z")
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.set_zlim(0, 1)
ax.view_init(elev=22, azim=-55)
ax.legend(loc="upper left", frameon=False)

fig.tight_layout()
out = "E:\scatter3d_reproduce.png"
fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
print("saved:", out)
