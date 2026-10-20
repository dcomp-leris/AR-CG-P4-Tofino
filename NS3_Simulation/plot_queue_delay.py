import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

data = {
    'Scenario': [
        'S1: Classic Video\n(Not-ECT)',
        'S2: Uncontrolled L4S\n(6 Mbps ECT(1))',
        'S3: Pure Responsive\n(UDP Prague)',
        'S4: Video Surge\n(12 Mbps ECT(1))',
        'S5: Controlled L4S\n(3.5 Mbps ECT(1))'
    ],
    'C2_TCP_Latency_ms': [1.8, 65.3, 2.1, 145.0, 5.2],
    'C3_Video_Latency_ms': [118.5, 63.8, 2.3, 142.1, 5.4],
}

df = pd.DataFrame(data)

fig, ax = plt.subplots(figsize=(8, 5))
x = np.arange(len(df['Scenario']))
width = 0.35

c_tcp = '#2b5c8f'
c_video = '#e05d5d'

rects1 = ax.bar(x - width/2, df['C2_TCP_Latency_ms'], width, label='C2: L4S TCP Prague', color=c_tcp)
rects2 = ax.bar(x + width/2, df['C3_Video_Latency_ms'], width, label='C3: Video Stream', color=c_video)

ax.set_ylabel('Mean Queueing Delay (ms)', fontweight='bold')
ax.set_title('Figure A.1a: Mean Queueing Delay: Prague and Video', fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(df['Scenario'], fontsize=8)
ax.axhline(y=1.0, color='green', linestyle='--', linewidth=1.5, label='L4S CE Target (1 ms)')
ax.legend()
ax.grid(True, linestyle=':', alpha=0.6)

for bar in rects1 + rects2:
    height = bar.get_height()
    ax.annotate(f'{height:.1f}ms',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points",
                ha='center', va='bottom', fontsize=8, fontweight='bold')

plt.tight_layout()
plt.savefig('figure_A1a_queueing_delay.png', dpi=300)
