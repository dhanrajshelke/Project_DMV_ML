import React, { useState } from 'react';

// Color Palette for Cybersecurity Aesthetics
const PALETTE = [
  '#06B6D4', // Cyan
  '#EF4444', // Red (DDoS / Threat)
  '#F59E0B', // Amber (PortScan / Warning)
  '#8B5CF6', // Purple (Patator / Brute)
  '#10B981', // Emerald (Benign / Safe)
  '#3B82F6', // Blue
  '#EC4899', // Pink
  '#14B8A6'  // Teal
];

const getColorForLabel = (label, idx) => {
  const l = String(label).toUpperCase();
  if (l.includes('BENIGN') || l.includes('NORMAL')) return '#10B981';
  if (l.includes('DDOS') || l.includes('DOS')) return '#EF4444';
  if (l.includes('PORTSCAN')) return '#F59E0B';
  if (l.includes('PATATOR') || l.includes('BRUTE')) return '#8B5CF6';
  if (l.includes('BOTNET')) return '#EC4899';
  if (l.includes('SQL') || l.includes('WEB')) return '#F97316';
  return PALETTE[idx % PALETTE.length];
};

/**
 * 1. Attack Distribution Donut Chart
 */
export function AttackDonutChart({ labelBreakdown = {}, totalRecords = 0 }) {
  const [hoveredSlice, setHoveredSlice] = useState(null);

  const entries = Object.entries(labelBreakdown);
  const total = totalRecords || entries.reduce((acc, [, val]) => acc + val, 0) || 1;

  // SVG Geometry
  const size = 260;
  const center = size / 2;
  const radius = 80;
  const strokeWidth = 28;
  const circumference = 2 * Math.PI * radius;

  let currentAngle = -90; // Start at top
  const slices = entries.map(([label, count], idx) => {
    const fraction = count / total;
    const strokeDasharray = `${fraction * circumference} ${circumference}`;
    const strokeDashoffset = -((currentAngle + 90) / 360) * circumference;
    const color = getColorForLabel(label, idx);
    const angle = currentAngle;
    currentAngle += fraction * 360;
    const pct = (fraction * 100).toFixed(1);

    return { label, count, pct, color, strokeDasharray, strokeDashoffset, angle };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', minHeight: '220px' }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Background Track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth={strokeWidth}
          />
          {/* Donut Slices */}
          {slices.map((slice, idx) => (
            <circle
              key={idx}
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={slice.color}
              strokeWidth={hoveredSlice === slice.label ? strokeWidth + 6 : strokeWidth}
              strokeDasharray={slice.strokeDasharray}
              strokeDashoffset={slice.strokeDashoffset}
              transform={`rotate(-90 ${center} ${center})`}
              style={{
                transition: 'stroke-width 0.25s ease, filter 0.25s ease',
                cursor: 'pointer',
                filter: hoveredSlice === slice.label ? `drop-shadow(0 0 10px ${slice.color})` : 'none'
              }}
              onMouseEnter={() => setHoveredSlice(slice.label)}
              onMouseLeave={() => setHoveredSlice(null)}
            />
          ))}
          {/* Centered Counter */}
          <text x={center} y={center - 8} textAnchor="middle" fill="#FFFFFF" fontSize="22" fontWeight="700" fontFamily="Segoe UI, sans-serif">
            {hoveredSlice ? slices.find(s => s.label === hoveredSlice)?.count : total}
          </text>
          <text x={center} y={center + 14} textAnchor="middle" fill="var(--fg-muted)" fontSize="11" fontFamily="Segoe UI, sans-serif">
            {hoveredSlice ? slices.find(s => s.label === hoveredSlice)?.label : 'Total Flows'}
          </text>
          {hoveredSlice && (
            <text x={center} y={center + 30} textAnchor="middle" fill={slices.find(s => s.label === hoveredSlice)?.color} fontSize="11" fontWeight="600">
              {slices.find(s => s.label === hoveredSlice)?.pct}%
            </text>
          )}
        </svg>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 14px', marginTop: '12px', justifyContent: 'center' }}>
        {slices.map((slice, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11px',
              cursor: 'pointer',
              opacity: hoveredSlice && hoveredSlice !== slice.label ? 0.4 : 1,
              transition: 'opacity 0.2s'
            }}
            onMouseEnter={() => setHoveredSlice(slice.label)}
            onMouseLeave={() => setHoveredSlice(null)}
          >
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: slice.color }}></span>
            <span style={{ color: 'var(--fg-default)', fontWeight: 500 }}>{slice.label}</span>
            <span style={{ color: 'var(--fg-muted)', fontFamily: 'var(--font-mono)' }}>({slice.pct}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * 2. Top Target Destination Ports Graphical Column Chart
 */
export function DestinationPortsBarChart({ portCounts = {}, totalRecords = 0 }) {
  const [hoveredPort, setHoveredPort] = useState(null);

  const entries = Object.entries(portCounts);
  if (!entries.length) {
    return <p style={{ color: 'var(--fg-muted)' }}>No port telemetry available.</p>;
  }

  const maxHits = Math.max(...entries.map(([, v]) => v), 1);
  const chartHeight = 170;
  const chartWidth = 460;
  const paddingLeft = 35;
  const paddingBottom = 40;
  const paddingTop = 25;
  const barAreaWidth = chartWidth - paddingLeft - 20;
  const barAreaHeight = chartHeight - paddingBottom - paddingTop;
  const colWidth = Math.min(barAreaWidth / entries.length - 12, 42);

  const getServiceName = (port) => {
    switch (String(port)) {
      case '21': return 'FTP';
      case '22': return 'SSH';
      case '23': return 'Telnet';
      case '80': return 'HTTP';
      case '443': return 'HTTPS';
      case '139': return 'NetBIOS';
      case '445': return 'SMB';
      case '3306': return 'MySQL';
      case '8080': return 'Proxy';
      default: return `P-${port}`;
    }
  };

  return (
    <div style={{ width: '100%', overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} style={{ width: '100%', maxHeight: '230px' }}>
        {/* Y-Axis Horizontal Gridlines */}
        {[0, 0.5, 1].map((pct, i) => {
          const y = paddingTop + barAreaHeight * (1 - pct);
          const val = Math.round(maxHits * pct);
          return (
            <g key={i}>
              <line x1={paddingLeft} y1={y} x2={chartWidth - 10} y2={y} stroke="rgba(255, 255, 255, 0.08)" strokeDasharray="3 3" />
              <text x={paddingLeft - 6} y={y + 3} textAnchor="end" fill="var(--fg-muted)" fontSize="9" fontFamily="var(--font-mono)">
                {val}
              </text>
            </g>
          );
        })}

        {/* Vertical Bars */}
        {entries.map(([port, count], idx) => {
          const barHeight = (count / maxHits) * barAreaHeight;
          const x = paddingLeft + idx * (barAreaWidth / entries.length) + 6;
          const y = paddingTop + barAreaHeight - barHeight;
          const isHovered = hoveredPort === port;
          const svc = getServiceName(port);
          const pctTraffic = totalRecords ? ((count / totalRecords) * 100).toFixed(0) : 0;

          return (
            <g
              key={port}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredPort(port)}
              onMouseLeave={() => setHoveredPort(null)}
            >
              {/* Value Label above Bar */}
              <text
                x={x + colWidth / 2}
                y={y - 5}
                textAnchor="middle"
                fill={isHovered ? '#38BDF8' : 'var(--fg-muted)'}
                fontSize="10"
                fontWeight={isHovered ? 700 : 500}
                fontFamily="var(--font-mono)"
              >
                {count}
              </text>

              {/* Bar Rect */}
              <rect
                x={x}
                y={y}
                width={colWidth}
                height={Math.max(barHeight, 3)}
                rx={4}
                fill={isHovered ? '#06B6D4' : 'url(#portGrad)'}
                style={{
                  transition: 'all 0.25s ease',
                  filter: isHovered ? 'drop-shadow(0 0 8px rgba(6, 182, 212, 0.6))' : 'none'
                }}
              />

              {/* Port & Service Label */}
              <text
                x={x + colWidth / 2}
                y={chartHeight - paddingBottom + 14}
                textAnchor="middle"
                fill={isHovered ? '#FFFFFF' : 'var(--fg-default)'}
                fontSize="10"
                fontWeight="600"
              >
                {svc}
              </text>
              <text
                x={x + colWidth / 2}
                y={chartHeight - paddingBottom + 26}
                textAnchor="middle"
                fill="var(--fg-muted)"
                fontSize="9"
                fontFamily="var(--font-mono)"
              >
                :{port}
              </text>
            </g>
          );
        })}

        {/* Gradient Definition */}
        <defs>
          <linearGradient id="portGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38BDF8" />
            <stop offset="100%" stopColor="#0284C7" />
          </linearGradient>
        </defs>
      </svg>
    </div>
  );
}

/**
 * 3. Random Forest Feature Importance Visual Horizontal Graph
 */
export function FeatureImportanceBarChart({ featureImportances = [] }) {
  if (!featureImportances || !featureImportances.length) {
    return <p style={{ color: 'var(--fg-muted)' }}>Feature metadata loading...</p>;
  }

  const maxImp = Math.max(...featureImportances.map(f => f.importance || f.Importance || 0.1), 0.01);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {featureImportances.slice(0, 7).map((item, idx) => {
        const feat = item.feature || item.Feature || `Feature ${idx + 1}`;
        const imp = item.importance || item.Importance || 0.05;
        const pct = (imp * 100).toFixed(1);
        const widthPct = Math.min((imp / maxImp) * 100, 100);

        return (
          <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  backgroundColor: 'rgba(139, 92, 246, 0.2)',
                  color: '#A78BFA',
                  padding: '1px 5px',
                  borderRadius: '3px',
                  fontFamily: 'var(--font-mono)'
                }}>
                  #{idx + 1}
                </span>
                <span style={{ color: 'var(--fg-default)', fontWeight: 500 }}>{feat}</span>
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#C4B5FD', fontWeight: 600 }}>
                {pct}%
              </span>
            </div>

            <div style={{
              width: '100%',
              height: '8px',
              backgroundColor: 'var(--bg-inset)',
              borderRadius: '4px',
              overflow: 'hidden'
            }}>
              <div
                style={{
                  width: `${widthPct}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #6366F1, #8B5CF6, #A855F7)',
                  borderRadius: '4px',
                  transition: 'width 0.4s ease'
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * 4. Isolation Forest Anomaly Score Distribution Histogram (True Vertical Histogram)
 */
export function AnomalyHistogramChart({ histogramData = [], totalRecords = 0, anomalyCount = 0 }) {
  const [hoveredBin, setHoveredBin] = useState(null);

  if (!histogramData || !histogramData.length) {
    return <p style={{ color: 'var(--fg-muted)' }}>No histogram available.</p>;
  }

  const maxCount = Math.max(...histogramData.map(b => b.count), 1);
  const chartHeight = 175;
  const chartWidth = 520;
  const paddingLeft = 35;
  const paddingBottom = 35;
  const paddingTop = 25;
  const barAreaWidth = chartWidth - paddingLeft - 20;
  const barAreaHeight = chartHeight - paddingBottom - paddingTop;
  const colWidth = (barAreaWidth / histogramData.length) - 6;

  // Threshold x-coordinate at 0.75 (which is 75% along the 0.0 - 1.0 range)
  const thresholdX = paddingLeft + barAreaWidth * 0.75;

  return (
    <div style={{ width: '100%', overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} style={{ width: '100%', maxHeight: '230px' }}>
        {/* Y-Axis Gridlines */}
        {[0, 0.5, 1].map((pct, i) => {
          const y = paddingTop + barAreaHeight * (1 - pct);
          const val = Math.round(maxCount * pct);
          return (
            <g key={i}>
              <line x1={paddingLeft} y1={y} x2={chartWidth - 10} y2={y} stroke="rgba(255, 255, 255, 0.08)" strokeDasharray="3 3" />
              <text x={paddingLeft - 6} y={y + 3} textAnchor="end" fill="var(--fg-muted)" fontSize="9" fontFamily="var(--font-mono)">
                {val}
              </text>
            </g>
          );
        })}

        {/* Anomalous Outlier Zone Background (> 0.75) */}
        <rect
          x={thresholdX}
          y={paddingTop}
          width={chartWidth - 10 - thresholdX}
          height={barAreaHeight}
          fill="rgba(239, 68, 68, 0.08)"
          rx={2}
        />

        {/* Histogram Columns */}
        {histogramData.map((bin, idx) => {
          const barHeight = (bin.count / maxCount) * barAreaHeight;
          const x = paddingLeft + idx * (barAreaWidth / histogramData.length) + 3;
          const y = paddingTop + barAreaHeight - barHeight;
          const isHovered = hoveredBin === idx;

          // Color classification: Safe Green -> Amber -> Alert Crimson
          const color = idx >= 7 ? '#EF4444' : idx >= 4 ? '#F59E0B' : '#10B981';

          return (
            <g
              key={idx}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredBin(idx)}
              onMouseLeave={() => setHoveredBin(null)}
            >
              {/* Value Label above Bar */}
              {bin.count > 0 && (
                <text
                  x={x + colWidth / 2}
                  y={y - 5}
                  textAnchor="middle"
                  fill={isHovered ? '#FFFFFF' : color}
                  fontSize="9"
                  fontWeight="600"
                  fontFamily="var(--font-mono)"
                >
                  {bin.count}
                </text>
              )}

              {/* Bar Rect */}
              <rect
                x={x}
                y={y}
                width={colWidth}
                height={Math.max(barHeight, 2)}
                rx={3}
                fill={color}
                opacity={isHovered ? 1 : 0.85}
                style={{
                  transition: 'all 0.2s ease',
                  filter: isHovered ? `drop-shadow(0 0 8px ${color})` : 'none'
                }}
              />

              {/* Bin Range Label */}
              <text
                x={x + colWidth / 2}
                y={chartHeight - paddingBottom + 14}
                textAnchor="middle"
                fill={idx >= 7 ? '#F87171' : 'var(--fg-muted)'}
                fontSize="8"
                fontFamily="var(--font-mono)"
              >
                {bin.range.split('-')[0]}
              </text>
            </g>
          );
        })}

        {/* Threshold Indicator Line (> 0.75) */}
        <line
          x1={thresholdX}
          y1={paddingTop - 6}
          x2={thresholdX}
          y2={chartHeight - paddingBottom}
          stroke="#EF4444"
          strokeWidth="1.5"
          strokeDasharray="4 3"
        />
        <text
          x={thresholdX + 4}
          y={paddingTop + 6}
          fill="#EF4444"
          fontSize="9"
          fontWeight="700"
        >
          Anomaly &gt; 0.75
        </text>

        {/* X Axis Title */}
        <text
          x={chartWidth / 2 + 10}
          y={chartHeight - 4}
          textAnchor="middle"
          fill="var(--fg-muted)"
          fontSize="10"
        >
          Normalized Anomaly Score (0.0 Normal → 1.0 Extreme Outlier)
        </text>
      </svg>
    </div>
  );
}

/**
 * 5. Flow Telemetry Scatter / Cluster Profile (Duration vs Packet Rate)
 */
export function FlowTelemetryScatterPlot({ records = [] }) {
  const [hoveredPoint, setHoveredPoint] = useState(null);

  if (!records || !records.length) return null;

  const sample = records.slice(0, 40);
  const chartWidth = 520;
  const chartHeight = 160;
  const padding = 30;

  const durations = sample.map(r => Number(r['Flow Duration']) || 100);
  const maxDur = Math.max(...durations, 1000);
  const minDur = Math.min(...durations, 1);

  const scores = sample.map(r => Number(r['Anomaly Score']) || 0.1);

  return (
    <div style={{ width: '100%', overflowX: 'auto', position: 'relative' }}>
      <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} style={{ width: '100%', maxHeight: '200px' }}>
        {/* Background Grid */}
        {[0.25, 0.5, 0.75, 1].map((pct, i) => (
          <line
            key={i}
            x1={padding}
            y1={padding + (chartHeight - 2 * padding) * (1 - pct)}
            x2={chartWidth - padding}
            y2={padding + (chartHeight - 2 * padding) * (1 - pct)}
            stroke="rgba(255, 255, 255, 0.05)"
          />
        ))}

        {/* Scatter Points */}
        {sample.map((r, i) => {
          const dur = Number(r['Flow Duration']) || 100;
          const score = Number(r['Anomaly Score']) || 0.1;
          const isBenign = String(r['Model Prediction']).toUpperCase().includes('BENIGN');
          const color = isBenign ? '#10B981' : '#EF4444';

          const x = padding + ((dur - minDur) / (maxDur - minDur || 1)) * (chartWidth - 2 * padding);
          const y = padding + (1 - score) * (chartHeight - 2 * padding);
          const isHovered = hoveredPoint === i;

          return (
            <g
              key={i}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredPoint(i)}
              onMouseLeave={() => setHoveredPoint(null)}
            >
              <circle
                cx={x}
                cy={y}
                r={isHovered ? 7 : 4}
                fill={color}
                opacity={isHovered ? 1 : 0.75}
                style={{
                  transition: 'all 0.2s ease',
                  filter: isHovered ? `drop-shadow(0 0 6px ${color})` : 'none'
                }}
              />
            </g>
          );
        })}

        {/* Labels */}
        <text x={padding} y={chartHeight - 8} fill="var(--fg-muted)" fontSize="9">
          Flow Duration (Time) →
        </text>
        <text x={chartWidth - padding} y={padding - 10} textAnchor="end" fill="var(--fg-muted)" fontSize="9">
          ↑ Anomaly Score
        </text>
      </svg>

      {/* Hover Info Tooltip */}
      {hoveredPoint !== null && sample[hoveredPoint] && (
        <div style={{
          position: 'absolute',
          top: '8px',
          right: '16px',
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          border: '1px solid var(--border-default)',
          borderRadius: '6px',
          padding: '6px 10px',
          fontSize: '11px',
          pointerEvents: 'none',
          boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
        }}>
          <div><strong>{sample[hoveredPoint].Record_ID}</strong>: <span style={{ color: '#38BDF8' }}>{sample[hoveredPoint]['Model Prediction']}</span></div>
          <div style={{ color: 'var(--fg-muted)', fontSize: '10px' }}>
            Port: {sample[hoveredPoint]['Destination Port']} | Anomaly: {sample[hoveredPoint]['Anomaly Score']}
          </div>
        </div>
      )}
    </div>
  );
}
