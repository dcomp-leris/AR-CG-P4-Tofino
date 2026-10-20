import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
})

data = {
    'Scenario': [
        'S1: Classic Video\n(Not-ECT)',
        'S2: Uncontrolled L4S\n(6 Mbps ECT(1))',
        'S3: Pure Responsive\n(UDP Prague)',
        'S4: Video Surge\n(12 Mbps ECT(1))',
        'S5: Controlled L4S\n(3.5 Mbps ECT(1))'
    ],
    'C2_TCP_Throughput_Mbps': [4.38, 1.66, 3.85, 0.85, 4.25],
    'C3_Video_Throughput_Mbps': [3.68, 3.35, 3.92, 5.20, 3.50],
}

df = pd.DataFrame(data)

fig, ax = plt.subplots(figsize=(8, 5))
x = np.arange(len(df['Scenario']))
width = 0.35

c_tcp = '#2b5c8f'
c_video = '#e05d5d'

rects1 = ax.bar(x - width/2, df['C2_TCP_Throughput_Mbps'], width, label='C2: L4S TCP', color=c_tcp)
rects2 = ax.bar(x + width/2, df['C3_Video_Throughput_Mbps'], width, label='C3: Video Stream', color=c_video)

ax.set_ylabel('Throughput (Mbps)', fontweight='bold')
ax.set_title('Figure A.1b: Bandwidth Allocation & Throughput', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(df['Scenario'], fontsize=10)
ax.legend()
ax.grid(True, linestyle=':', alpha=0.6)

for bar in rects1 + rects2:
    height = bar.get_height()
    ax.annotate(f'{height:.2f}',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points",
                ha='center', va='bottom', fontsize=10)

plt.tight_layout()
plt.savefig('figure_A1b_throughput.png', dpi=300)
