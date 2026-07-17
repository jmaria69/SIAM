import React, { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:8001';

function riskColor(score) {
  if (score >= 60) return 'text-rose-400';
  if (score >= 30) return 'text-amber-400';
  return 'text-emerald-400';
}

export default function ExecutivePanel() {
  const [panel, setPanel] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch(`${API_BASE}/v1/reports/executive`);
        if (res.ok) setPanel(await res.json());
      } catch (err) {
        console.error('Error cargando panel ejecutivo:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="bg-slate-950 text-slate-400 min-h-screen p-6 font-sans italic">Cargando panel ejecutivo...</div>;
  }
  if (!panel) {
    return <div className="bg-slate-950 text-rose-400 min-h-screen p-6 font-sans">No se pudo cargar el panel ejecutivo.</div>;
  }

  return (
    <div className="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6 font-sans">
      <header className="mb-6 border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <span className="text-amber-400">📊</span> Panel Ejecutivo
        </h1>
        <p className="text-sm text-slate-400 mt-1">Resumen de seguridad para dirección — sin jerga técnica</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg col-span-1">
          <h3 className="text-slate-400 text-sm font-medium">Nivel de riesgo</h3>
          <p className={`text-5xl font-extrabold mt-2 ${riskColor(panel.nivel_riesgo)}`}>{panel.nivel_riesgo}</p>
          <p className="text-xs text-slate-500 mt-1">sobre 100</p>
        </div>
        <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium">Incidentes abiertos</h3>
          <p className="text-4xl font-extrabold mt-2 text-blue-400">{panel.incidentes_abiertos}</p>
        </div>
        <div
          className={`p-5 rounded-xl border shadow-lg ${
            panel.incidentes_criticos_abiertos > 0 ? 'bg-rose-950 border-rose-600 animate-pulse' : 'bg-slate-900 border-slate-800'
          }`}
        >
          <h3 className="text-slate-400 text-sm font-medium">Críticos sin resolver</h3>
          <p className="text-4xl font-extrabold mt-2">{panel.incidentes_criticos_abiertos}</p>
        </div>
      </div>

      <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg mb-6">
        <h2 className="text-lg font-semibold mb-2">Resumen</h2>
        <p className="text-slate-300 text-sm">{panel.resumen}</p>
      </div>

      <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg">
        <h2 className="text-lg font-semibold mb-3">Principales amenazas</h2>
        {panel.principales_amenazas.length === 0 ? (
          <p className="text-slate-500 italic text-sm">Ninguna amenaza crítica activa.</p>
        ) : (
          <ul className="space-y-2">
            {panel.principales_amenazas.map((t, idx) => (
              <li key={idx} className="flex justify-between text-sm border-b border-slate-900 pb-2">
                <span>{t.titulo}</span>
                <span className="text-rose-400 font-bold uppercase text-xs">{t.severidad}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <p className="text-xs text-slate-600 mt-4">
        Incidentes resueltos históricamente: {panel.incidentes_resueltos_total}
      </p>
    </div>
  );
}
