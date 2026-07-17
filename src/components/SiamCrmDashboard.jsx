import React, { useState, useEffect } from 'react';

export default function SiamCrmDashboard() {
  const [metrics, setMetrics] = useState({
    summary: {
      total_tickets: 0,
      status_distribution: { NUEVO: 0, EN_PROGRESO: 0, RESUELTO: 0 },
      critical_alerts: 0,
      olga_auto_recovery_rate: "0%"
    },
    recent_tickets: []
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        // Corregido: el backend escucha en :8001 (ver .env / docker-compose.yml),
        // no en :8000 como decía antes — por eso el dashboard nunca cargaba datos.
        const res = await fetch('http://localhost:8001/v1/metrics');
        if (res.ok) {
          const data = await res.json();
          setMetrics(data);
        }
      } catch (err) {
        console.error("Error cargando el bus de datos SIEM:", err);
      } finally {
        setLoading(false);
      }
    }

    loadData();
    const interval = setInterval(loadData, 2000);
    return () => clearInterval(interval);
  }, []);

  const { summary, recent_tickets } = metrics;
  const total = summary.total_tickets || 1;
  
  // Cálculo de porcentajes para las barras dinámicas
  const pctNuevo = (summary.status_distribution.NUEVO / total) * 100;
  const pctProgreso = (summary.status_distribution.EN_PROGRESO / total) * 100;
  const pctResuelto = (summary.status_distribution.RESUELTO / total) * 100;

  return (
    <div className="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-6 font-sans">
      {/* Encabezado */}
      <header className="mb-6 border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <span className="text-blue-500">🔵</span> SIEM Control Tower ORCHESTRATOR ACTIVE
        </h1>
        <p className="text-sm text-slate-400 mt-1">Bus de Integración Multi-Proveedor & Agente OLGA (Métricas Expandidas)</p>
        <p className="text-xs text-slate-500">WSL2: Ubuntu-22.04</p>
      </header>

      {/* Grid de KPIs */}
      <main className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium">Volumen Ingesta</h3>
          <p className="text-3xl font-extrabold mt-2 text-blue-400">{summary.total_tickets} Tickets</p>
        </div>
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium">En Progreso (CDM)</h3>
          <p className="text-3xl font-extrabold mt-2 text-amber-400">{summary.status_distribution.EN_PROGRESO}</p>
        </div>
        <div className={`p-4 rounded-xl border shadow-lg transition-all duration-300 ${
          summary.critical_alerts > 0 
            ? 'bg-rose-950 border-rose-500 animate-pulse text-white' 
            : 'bg-slate-900 border-slate-800'
        }`}>
          <h3 className="text-slate-400 text-sm font-medium">Alertas Críticas</h3>
          <p className={`text-3xl font-extrabold mt-2 ${summary.critical_alerts > 0 ? 'text-white' : 'text-rose-500'}`}>
            {summary.critical_alerts}
          </p>
        </div>
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium">Auto-Recuperación (OLGA)</h3>
          <p className="text-3xl font-extrabold mt-2 text-emerald-400">{summary.olga_auto_recovery_rate}</p>
        </div>
      </main>

      {/* Gráficos y Latencias */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Distribución Volumétrica */}
        <div class="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg">
          <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">📊 Distribución Volumétrica por Estado CDM</h2>
          <div class="space-y-4">
            <div>
              <div class="flex justify-between text-xs mb-1">
                <span>NUEVO (Ingresado sin asignar)</span>
                <span>{summary.status_distribution.NUEVO}</span>
              </div>
              <div class="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
                <div class="bg-blue-500 h-full transition-all duration-500" style={{ width: `${pctNuevo}%` }}></div>
              </div>
            </div>
            <div>
              <div class="flex justify-between text-xs mb-1">
                <span>EN PROGRESO (Diagnosticando / Procesando)</span>
                <span>{summary.status_distribution.EN_PROGRESO}</span>
              </div>
              <div class="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
                <div class="bg-amber-500 h-full transition-all duration-500" style={{ width: `${pctProgreso}%` }}></div>
              </div>
            </div>
            <div>
              <div class="flex justify-between text-xs mb-1">
                <span>RESUELTO (Finalizado con Éxito)</span>
                <span>{summary.status_distribution.RESUELTO}</span>
              </div>
              <div class="w-full bg-slate-800 h-3 rounded-full overflow-hidden">
                <div class="bg-emerald-500 h-full transition-all duration-500" style={{ width: `${pctResuelto}%` }}></div>
              </div>
            </div>
          </div>
        </div>

        {/* Histograma de Latencia Rehecho en CSS Limpio */}
        <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-semibold mb-2 flex items-center gap-2">📈 Historial de Latencia del Gateway</h2>
            <p className="text-xs text-slate-400 mb-4">Live — Simulación Activa</p>
          </div>
          
          {/* Gráfico de Barras de Latencia Dinámico */}
          <div className="flex items-end gap-2 h-24 px-2 items-stretch pt-4">
            <div className="bg-slate-800 flex-1 rounded-t" style={{ height: '35%' }}></div>
            <div className="bg-slate-800 flex-1 rounded-t" style={{ height: '42%' }}></div>
            <div className="bg-slate-800 flex-1 rounded-t" style={{ height: '28%' }}></div>
            <div className="bg-slate-800 flex-1 rounded-t" style={{ height: '38%' }}></div>
            <div className={`flex-1 rounded-t transition-all ${summary.critical_alerts > 0 ? 'bg-rose-600 animate-pulse' : 'bg-slate-800'}`} style={{ height: '75%' }}></div>
            <div className="bg-emerald-600 flex-1 rounded-t" style={{ height: '25%' }}></div>
          </div>

          <div className="border-t border-slate-800 pt-3 mt-4 flex justify-between text-xs text-slate-400 font-mono">
            <span>Hace 30m</span>
            <span className={summary.critical_alerts > 0 ? "text-rose-400 font-bold" : "text-emerald-400"}>
              {summary.critical_alerts > 0 ? "ALERTA ACTIVA" : "Estable Ahora"}
            </span>
          </div>
        </div>
      </section>

      {/* Cola de Eventos Normalizados */}
      <footer className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-lg">
        <h2 className="text-lg font-semibold mb-2 flex items-center gap-2">📋 Cola de Eventos Normalizados (Canonical Data Model)</h2>
        <div className="bg-slate-950 rounded-lg p-3 font-mono text-xs overflow-x-auto max-h-48 overflow-y-auto">
          <div className="text-slate-500 border-b border-slate-800 pb-2 mb-2 grid grid-cols-6 gap-2 font-bold">
            <div>UUID Interno</div>
            <div>ID Externo</div>
            <div>Origen</div>
            <div>Asunto / Incidencia</div>
            <div>Criticidad</div>
            <div>Estado SIEM</div>
          </div>
          <div className="space-y-2">
            {recent_tickets.length === 0 ? (
              <div className="text-slate-500 italic py-2">Esperando inyección de Webhooks...</div>
            ) : (
              recent_tickets.map((t) => (
                <div key={t.ticket_id} className="grid grid-cols-6 gap-2 text-slate-300 py-1 border-b border-slate-900 hover:bg-slate-900/50 rounded px-1 items-center">
                  <div className="text-blue-400 truncate" title={t.ticket_id}>{t.ticket_id.substring(0, 8)}...</div>
                  <div className="font-bold">{t.external_id}</div>
                  <div className="text-slate-400 text-xs">{t.provider}</div>
                  <div className="truncate text-xs" title={t.summary}>{t.summary}</div>
                  <div className={t.priority === 'HIGH' ? 'text-rose-400 font-bold animate-pulse' : 'text-slate-400'}>
                    {t.priority}
                  </div>
                  <div>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      {t.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </footer>
    </div>
  );
}
