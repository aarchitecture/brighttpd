const benchmarks = {
  http: {
    small: {
      command: "wrk --latency -t4 -c256 -d10s http://127.0.0.1:{port}/small",
      rps: { brighttpd: 312247.36, nginx: 150900.53 },
      latency: {
        brighttpd: { avg: "704.54us", p50: "341.00us", p75: "650.00us", p90: "1.84ms", p99: "4.23ms" },
        nginx: { avg: "1.58ms", p50: "0.93ms", p75: "2.17ms", p90: "3.81ms", p99: "8.16ms" },
      },
    },
    medium: {
      command: "wrk --latency -t4 -c256 -d10s http://127.0.0.1:{port}/medium",
      rps: { brighttpd: 80578.61, nginx: 52684.36 },
      latency: {
        brighttpd: { avg: "1.81ms", p50: "1.55ms", p75: "1.91ms", p90: "2.85ms", p99: "5.54ms" },
        nginx: { avg: "2.76ms", p50: "2.32ms", p75: "3.01ms", p90: "4.60ms", p99: "7.22ms" },
      },
    },
    big: {
      command: "wrk --latency -t2 -c64 -d10s http://127.0.0.1:{port}/big",
      rps: { brighttpd: 374.55, nginx: 349.08 },
      latency: {
        brighttpd: { avg: "123.78ms", p50: "76.27ms", p75: "133.28ms", p90: "278.56ms", p99: "554.03ms" },
        nginx: { avg: "111.07ms", p50: "88.60ms", p75: "105.10ms", p90: "169.08ms", p99: "546.49ms" },
      },
    },
    mixed: {
      command: "wrk --latency -t4 -c256 -d10s -s bench/mixed.lua http://127.0.0.1:{port}",
      rps: { brighttpd: 31310.6, nginx: 22414.17 },
      latency: {
        brighttpd: { avg: "5.13ms", p50: "1.24ms", p75: "8.70ms", p90: "14.38ms", p99: "28.70ms" },
        nginx: { avg: "7.43ms", p50: "2.20ms", p75: "14.31ms", p90: "18.53ms", p99: "34.60ms" },
      },
    },
  },
  tls: {
    small: {
      command: "wrk --latency -t4 -c256 -d10s https://127.0.0.1:{port}/small",
      rps: { brighttpd: 79934.67, nginx: 72195.33 },
      latency: {
        brighttpd: { avg: "2.40ms", p50: "2.08ms", p75: "2.60ms", p90: "3.57ms", p99: "5.75ms" },
        nginx: { avg: "2.41ms", p50: "1.85ms", p75: "2.99ms", p90: "4.49ms", p99: "9.18ms" },
      },
    },
    medium: {
      command: "wrk --latency -t4 -c256 -d10s https://127.0.0.1:{port}/medium",
      rps: { brighttpd: 14738.99, nginx: 10949.51 },
      latency: {
        brighttpd: { avg: "15.61ms", p50: "15.10ms", p75: "16.84ms", p90: "18.64ms", p99: "22.79ms" },
        nginx: { avg: "20.83ms", p50: "20.06ms", p75: "23.42ms", p90: "27.04ms", p99: "35.90ms" },
      },
    },
    big: {
      command: "wrk --latency -t2 -c64 -d10s https://127.0.0.1:{port}/big",
      rps: { brighttpd: 115.03, nginx: 108.55 },
      latency: {
        brighttpd: { avg: "539.75ms", p50: "540.77ms", p75: "556.19ms", p90: "575.72ms", p99: "583.04ms" },
        nginx: { avg: "575.34ms", p50: "575.07ms", p75: "587.15ms", p90: "600.80ms", p99: "652.51ms" },
      },
    },
    mixed: {
      command: "wrk --latency -t4 -c256 -d10s -s bench/mixed.lua https://127.0.0.1:{port}",
      rps: { brighttpd: 9900.95, nginx: 9124.35 },
      latency: {
        brighttpd: { avg: "363.43ms", p50: "6.65ms", p75: "651.01ms", p90: "1.39s", p99: "1.84s" },
        nginx: { avg: "5.64ms", p50: "3.59ms", p75: "5.54ms", p90: "14.91ms", p99: "29.11ms" },
      },
    },
  },
};

const workloads = ["small", "medium", "big", "mixed"];
const latencyColumns = ["avg", "p50", "p75", "p90", "p99"];

function formatNumber(value) {
  return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

function formatPercent(value) {
  const sign = value >= 0 ? "+" : "";
  return `${sign}${value.toFixed(2)}%`;
}

function parseDurationMs(value) {
  const match = value.match(/^([0-9.]+)(us|ms|s)$/);
  if (!match) {
    return Number.NaN;
  }

  const number = Number(match[1]);
  const unit = match[2];
  if (unit === "us") {
    return number / 1000;
  }
  if (unit === "s") {
    return number * 1000;
  }
  return number;
}

function percentChange(value, baseline) {
  return ((value - baseline) / baseline) * 100;
}

function comparisonClass(change, higherIsBetter) {
  if (change === 0) {
    return "";
  }
  return (higherIsBetter ? change > 0 : change < 0) ? "good" : "bad";
}

function baselineCell(value) {
  return `<td class="baseline">${value} <span class="delta">(100%)</span></td>`;
}

function comparisonCell(value, change, higherIsBetter) {
  const className = comparisonClass(change, higherIsBetter);
  return `<td class="${className}">${value} <span class="delta">(${formatPercent(change)})</span></td>`;
}

function renderTable(id, rows) {
  const target = document.querySelector(id);
  const body = workloads
    .map((workload) => {
      const row = rows[workload];
      const rpsChange = percentChange(row.rps.brighttpd, row.rps.nginx);
      const latencyCells = latencyColumns
        .flatMap((column) => {
          const nginx = row.latency.nginx[column];
          const brighttpd = row.latency.brighttpd[column];
          const change = percentChange(parseDurationMs(brighttpd), parseDurationMs(nginx));
          return [
            baselineCell(nginx),
            comparisonCell(brighttpd, change, false),
          ];
        })
        .join("");

      return `<tr>
        <td>${workload}</td>
        <td><code>${row.command}</code></td>
        ${baselineCell(formatNumber(row.rps.nginx))}
        ${comparisonCell(formatNumber(row.rps.brighttpd), rpsChange, true)}
        ${latencyCells}
      </tr>`;
    })
    .join("");

  target.innerHTML = `<table>
    <thead>
      <tr>
        <th rowspan="2">workload</th>
        <th rowspan="2">command</th>
        <th colspan="2">req/s (higher is better)</th>
        <th colspan="10">latency (lower is better)</th>
      </tr>
      <tr>
        <th>nginx</th>
        <th>brighttpd</th>
        ${latencyColumns.map((column) => `<th>nginx ${column}</th><th>brighttpd ${column}</th>`).join("")}
      </tr>
    </thead>
    <tbody>${body}</tbody>
  </table>`;
}

function compactNumber(value) {
  const number = Number(value);
  if (number >= 1000000) {
    return `${(number / 1000000).toFixed(1)}m`;
  }
  if (number >= 1000) {
    return `${(number / 1000).toFixed(number >= 10000 ? 0 : 1)}k`;
  }
  return number.toLocaleString(undefined, { maximumFractionDigits: 0 });
}

const valueLabelPlugin = {
  id: "valueLabel",
  afterDatasetsDraw(chart) {
    const { ctx } = chart;

    ctx.save();
    ctx.font = "12px ui-monospace, SFMono-Regular, Consolas, monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "bottom";

    chart.data.datasets.forEach((dataset, datasetIndex) => {
      const meta = chart.getDatasetMeta(datasetIndex);
      meta.data.forEach((bar, index) => {
        const value = dataset.data[index];
        const label = compactNumber(value);
        const tallEnoughForInsideLabel = Math.abs(bar.base - bar.y) > 24;
        const y = tallEnoughForInsideLabel ? bar.y + 18 : bar.y - 4;

        ctx.fillStyle = tallEnoughForInsideLabel ? "#fff" : "#222";
        ctx.fillText(label, bar.x, y);
      });
    });

    ctx.restore();
  },
};

function renderChart(id, title, rows) {
  if (!window.Chart) {
    return false;
  }

  const canvas = document.querySelector(id);

  new Chart(canvas, {
    type: "bar",
    data: {
      labels: workloads,
      datasets: [
        {
          label: "nginx",
          data: workloads.map((workload) => rows[workload].rps.nginx),
          backgroundColor: "#777",
          borderColor: "#777",
        },
        {
          label: "brighttpd",
          data: workloads.map((workload) => rows[workload].rps.brighttpd),
          backgroundColor: "#222",
          borderColor: "#222",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        title: {
          display: true,
          text: title,
        },
        legend: {
          position: "bottom",
        },
        tooltip: {
          callbacks: {
            label(context) {
              return `${context.dataset.label}: ${formatNumber(context.parsed.y)} req/s`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: {
            display: false,
          },
        },
        y: {
          type: "linear",
          position: "left",
          beginAtZero: true,
          title: {
            display: true,
            text: "req/s",
          },
          ticks: {
            callback: compactNumber,
          },
        },
      },
    },
    plugins: [valueLabelPlugin],
  });

  return true;
}

renderTable("#http-table", benchmarks.http);
renderTable("#tls-table", benchmarks.tls);

const chartsRendered = [
  renderChart("#http-chart", "HTTP", benchmarks.http),
  renderChart("#tls-chart", "TLS", benchmarks.tls),
].every(Boolean);

if (!chartsRendered) {
  document.body.classList.add("no-charts");
}
