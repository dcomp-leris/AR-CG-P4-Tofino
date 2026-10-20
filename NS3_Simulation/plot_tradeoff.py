import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
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
    'C3_Video_Loss_Pct': [12.4, 0.5, 0.0, 18.2, 0.0],
}

df = pd.DataFrame(data)

fig, ax = plt.subplots(figsize=(8, 5))

c_highlight = '#8e44ad'

for i, sc in enumerate(df['Scenario']):
    color = c_highlight if i == 4 else '#34495e'
    size = 180 if i == 4 else 100
    ax.scatter(df['C3_Video_Loss_Pct'][i], df['C2_TCP_Latency_ms'][i], color=color, s=size, zorder=5)
    ax.annotate(f"S{i+1}", xy=(df['C3_Video_Loss_Pct'][i] + 0.3, df['C2_TCP_Latency_ms'][i] + 1), fontsize=10, fontweight='bold')

ax.set_xlabel('Video Packet Loss (%) [Lower = Better Video QoE]', fontweight='bold')
ax.set_ylabel('L4S TCP Latency (ms) [Lower = Better L4S Protection]', fontweight='bold')
ax.set_title('Figure A.1d: Trade-Off Space: Video Loss vs L4S TCP Latency', fontweight='bold')
ax.grid(True, linestyle='--', alpha=0.6)

ax.axvspan(-0.5, 1.0, color='green', alpha=0.1, label='Zero Loss Region')
ax.axhspan(0, 10.0, color='blue', alpha=0.1, label='Low Latency Region (<10ms)')
ax.legend(loc='upper center')

plt.tight_layout()
plt.savefig('figure_A1d_tradeoff_matrix.png', dpi=300)
