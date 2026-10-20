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
    'C3_Video_Loss_Pct': [12.4, 0.5, 0.0, 18.2, 0.0],
}

df = pd.DataFrame(data)

fig, ax = plt.subplots(figsize=(8, 5))

bars_loss = ax.bar(df['Scenario'], df['C3_Video_Loss_Pct'], 
                   color=['#c0392b', '#e67e22', '#27ae60', '#c0392b', '#27ae60'], width=0.45)

ax.set_ylabel('Video Packet Loss (%)', fontweight='bold')
ax.set_title('Figure A.1c: Video Stream Packet Loss Rate', fontweight='bold')
ax.grid(True, linestyle=':', alpha=0.6)

for bar in bars_loss:
    height = bar.get_height()
    ax.annotate(f'{height:.1f}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3), textcoords="offset points",
                ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.tight_layout()
plt.savefig('figure_A1c_packet_loss.png', dpi=300)
