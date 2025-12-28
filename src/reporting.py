import matplotlib.pyplot as plt

def plot_failed_login_trend(trend_data):
    if not trend_data:
        print("No failed login trend data available.")
        return

    times = [row[0] for row in trend_data]
    counts = [row[1] for row in trend_data]

    plt.figure()
    plt.plot(times, counts, marker='o')
    plt.xticks(rotation=45)
    plt.xlabel("Time (Minute)")
    plt.ylabel("Failed Attempts")
    plt.title("Failed Login Attempts Over Time")
    plt.tight_layout()
    plt.show()
